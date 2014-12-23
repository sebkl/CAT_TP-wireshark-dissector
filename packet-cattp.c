/* packet-cattp.c
 * Routines for packet dissection of
 *      ETSI TS 102 127 v6.13.0  (Release 6 / 2009-0r45)
 * Copyright 2014-2014 by Sebastian Kloeppel <sebastian@kloeppel.mobi>
 *                        Cristina E. Vintila
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/wmem/wmem.h>
#include <epan/decode_as.h>
#include <epan/in_cksum.h>
#include <string.h>
#include <glib.h>
#include <epan/tvbuff.h>

#define CATTP_HBLEN 18
#define F_SYN 0x80
#define F_ACK 0x40
#define F_EAK 0x20
#define F_RST 0x10
#define F_NUL 0x08
#define F_SEG 0x04

/* bit masks for the first header byte. */
#define M_FLAGS 0xFC 	/* flags only, no version */
#define M_PDU_SYN 0xB8 	/* SYN (ACK,SEG dont care) without version*/
#define M_PDU_ACK 0xD0 	/* ACK (EAK,SEG,NUL dont care) without version */
#define M_PDU_RST 0xBC 	/* RST (ACK dont caret) without version */
#define M_VERSION 0x03 	/* only Version */

#define ICCID_PREFIX 0x98

#define CATTP_MAX_EAK_DISPLAY 10
#define CATTP_MAX_IDLEN_DISPLAY 40

typedef struct {
    gboolean syn;
    gboolean ack;
    gboolean eak;
    gboolean rst;
    gboolean nul;
    gboolean seg;
    guint8 flags;
    guint8 version;
    gushort rfu;
    guint8 hlen;
    gushort srcport;
    gushort dstport;
    gushort dlen;
    gushort seqno;
    gushort ackno;
    gushort wsize;
    gushort chksum;
    union {
        struct { /*SYN,SYNACK*/
            gushort maxpdu;
            gushort maxsdu;
            guint8 idlen;
            guint8* id;
        } syn;
        struct { /* ACK/EAK */
            guint8 eak_len;
            gushort* eaks;
            guint8* data;
        } ack;
        struct { /* RST */
            guint8 rc;
        } rst;
    } pdu;
} cattp_pck;

/* Function to register the dissector, called by plugin infrastructure. */
void proto_register_cattp();

/* Handoff */
void proto_reg_handoff_cattp();

/* Dissection of the base header */
static void dissect_cattp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Dissection of the packet flags */
static guint32 dissect_cattp_flags(tvbuff_t *tvb, proto_tree *cattp_tree, guint32 offset, cattp_pck *pck);

/* Dissection of SYN PDUs */
static guint32 dissect_cattp_synpdu(tvbuff_t *tvb, proto_tree *tree, guint32 offset, cattp_pck *pck);

/* Dissection of Extended Acknowledgement PDUs */
static guint32 dissect_cattp_eakpdu(tvbuff_t *tvb, proto_tree *tree, guint32 offset, cattp_pck *pck);

/* The heuristic dissector function checks if the UDP packet may be a cattp packet */
static gboolean dissect_cattp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

/* Resolve RS reason code to a textual representation. */
static const char* cattp_reset_reason_code(guint8 idx);

/* Verify if received checksum is correct. */
static gushort expected_chksum(gushort packet_chksum, gushort computed_chksum);

static int proto_cattp = -1;
static guint gcattp_port = 0;

static gint ett_cattp = -1;
static gint ett_cattp_id = -1;
static gint ett_cattp_flags = -1;
static gint ett_cattp_eaks = -1;

static int hf_cattp_flags = -1;
static int hf_cattp_flag_syn = -1;
static int hf_cattp_flag_ack = -1;
static int hf_cattp_flag_eak = -1;
static int hf_cattp_flag_rst = -1;
static int hf_cattp_flag_nul = -1;
static int hf_cattp_flag_seg = -1;
static int hf_cattp_version = -1;
static int hf_cattp_srcport = -1;
static int hf_cattp_dstport = -1;
static int hf_cattp_datalen = -1;
static int hf_cattp_seq = -1;
static int hf_cattp_ack = -1;
static int hf_cattp_windowsize = -1;
static int hf_cattp_checksum = -1;
static int hf_cattp_identification = -1;
static int hf_cattp_idlen = -1;
static int hf_cattp_maxpdu = -1;
static int hf_cattp_maxsdu = -1;
static int hf_cattp_rc = -1;
static int hf_cattp_eaklen = -1;
static int hf_cattp_eaks = -1;


static dissector_handle_t data_handle;

/* Place CATTP summary in proto tree */
static gboolean cattp_summary_in_tree = TRUE;

/* Flag to control whether to check the CATTP checksum */
static gboolean cattp_check_checksum = TRUE;


static const char* cattp_reset_reason_code(guint8 idx)
{
    static const char* cattp_reset_reason[] = {
        "Normal Ending",
        "Connection set-up failed, illegal parameters",
        "Temporarily unable to set up this connection",
        "Requested Port not available",
        "Unexpected PDU received",
        "Maximum retries exceeded",
        "Version not supported",
        "RFU"
    };

    static guint8 rcs = sizeof(cattp_reset_reason)/sizeof(cattp_reset_reason[0]);

    if (idx >= rcs) {
        return cattp_reset_reason[rcs-1];
    } else {
        return cattp_reset_reason[idx];
    }
}

void
proto_register_cattp(void)
{
    proto_cattp = proto_register_protocol (
                      "ETSI Card Application Toolkit Transport Protocol",	/* name */
                      "CAT-TP (ETSI)",/* short name */
                      "cattp"		/* abbrev */
                  );

    static hf_register_info hf[] = {
        {
            &hf_cattp_flags,
            {
                "Flags","cattp.flags", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_flag_syn,
            {
                "Synchronize Flag","cattp.flags.syn", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_flag_ack,
            {
                "Acknowledge Flag","cattp.flags.ack", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_flag_eak,
            {
                "Extended Acknowledge Flag","cattp.flags.eak", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_flag_rst,
            {
                "Reset Flag","cattp.flags.rst", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_flag_nul,
            {
                "NULL Flag","cattp.flags.nul", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_flag_seg,
            {
                "Segmentation Flag","cattp.flags.seg", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_version,
            {
                "Version","cattp.version", FT_UINT8, BASE_HEX, NULL, M_VERSION,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_srcport,
            {
                "Source Port","cattp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_dstport,
            {
                "Destination Port","cattp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_datalen,
            {
                "Data Length","cattp.datalen", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_seq,
            {
                "Sequence Number","cattp.seq", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_ack,
            {
                "Acknowledgement Number","cattp.ack", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_windowsize,
            {
                "Window Size","cattp.windowsize", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_checksum,
            {
                "Checksum","cattp.checksum", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_identification,
            {
                "Identification","cattp.identification", FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_maxpdu,
            {
                "Maxpdu","cattp.maxpdu", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_maxsdu,
            {
                "Maxsdu","cattp.maxsdu", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_rc,
            {
                "Reason Code","cattp.rc", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_idlen,
            {
                "Identification Length","cattp.idlen", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_eaks,
            {
                "Acknowledgement Number","cattp.eak", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_cattp_eaklen,
            {
                "Extended Acknowledgement Numbers","cattp.eaks", FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_cattp,
        &ett_cattp_flags,
        &ett_cattp_id,
        &ett_cattp_eaks
    };

    proto_register_field_array(proto_cattp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cattp(void)
{
    static dissector_handle_t cattp_handle;

    /* Create dissector handle */
    cattp_handle = create_dissector_handle(dissect_cattp, proto_cattp);
    data_handle = find_dissector("data");

    dissector_add_uint("udp.port", gcattp_port, cattp_handle);
    heur_dissector_add("udp",dissect_cattp_heur,proto_cattp);
}

static cattp_pck*
parse_cattp_packet(tvbuff_t *tvb)
{
    cattp_pck* ret;
    ret = wmem_alloc(wmem_packet_scope(),sizeof(cattp_pck));

    /* Check if the standard header fits in. */
    gulong len;
    len = tvb_captured_length(tvb);
    if (len < CATTP_HBLEN) {
        /* this is not a valid CATTP packet */
        return NULL;
    }

    /* Parse the header. */
    int offset;
    offset = 0;
    guint8 fb;
    fb = tvb_get_guint8(tvb,offset);
    offset++;

    ret->flags = fb & 0xFC; /* mask the flags only */

    ret->syn = (fb & F_SYN) > 0;
    ret->ack = (fb & F_ACK) > 0;
    ret->eak = (fb & F_EAK) > 0;
    ret->rst = (fb & F_RST) > 0;
    ret->nul = (fb & F_NUL) > 0;
    ret->seg = (fb & F_SEG) > 0;

    ret->version = fb & M_VERSION; /* mask the version only */

    ret->rfu = tvb_get_ntohs(tvb,offset);
    offset+=2;
    ret->hlen = tvb_get_guint8(tvb,offset);
    offset++;
    ret->srcport = tvb_get_ntohs(tvb,offset);
    offset+=2;
    ret->dstport = tvb_get_ntohs(tvb,offset);
    offset+=2;
    ret->dlen = tvb_get_ntohs(tvb,offset);
    offset+=2;
    ret->seqno = tvb_get_ntohs(tvb,offset);
    offset+=2;
    ret->ackno = tvb_get_ntohs(tvb,offset);
    offset+=2;
    ret->wsize = tvb_get_ntohs(tvb,offset);
    offset+=2;
    ret->chksum = tvb_get_ntohs(tvb,offset);
    offset+=2;

    /* Verify the header: */
    if ((ret->hlen + ret->dlen) != len) {
        /* Invalid header/data len -> abort */
        return NULL;
    }

    /* Parse SYN (only syn flag set) */
    if ((ret->flags & M_PDU_SYN) == F_SYN) {
        ret->pdu.syn.maxpdu = tvb_get_ntohs(tvb,offset);
        offset+=2;
        ret->pdu.syn.maxsdu = tvb_get_ntohs(tvb,offset);
        offset+=2;

        int idlen;
        idlen = ret->pdu.syn.idlen = tvb_get_guint8(tvb,offset);
        offset++;

        if (idlen != ret->hlen - offset) {
            return NULL;
        }

        guint8* id;
        id = wmem_alloc(wmem_packet_scope(),sizeof(guint8) * idlen + 1);

        int i;
        for (i = 0; i <idlen; i++) {
            id[i] = tvb_get_guint8(tvb,offset);
            offset++;
        }
        id[idlen] = 0;
        ret->pdu.syn.id = id;
        return ret;
    }

    /* Parse ACK PDU */
    if ((ret->flags & M_PDU_ACK) == F_ACK) {
        if (ret->flags & F_EAK) {
            int eak_len;
            eak_len = ret->pdu.ack.eak_len = (len-CATTP_HBLEN) >> 1;
            ret->pdu.ack.eaks = wmem_alloc(wmem_packet_scope(),sizeof(guint8) * eak_len +1);

            int i;
            for (i = 0; i < eak_len; i++) {
                ret->pdu.ack.eaks[i] = tvb_get_ntohs(tvb,offset);
                offset+=2;
            }
            ret->pdu.ack.eaks[eak_len] = 0;
        } else {
            ret->pdu.ack.eak_len = 0;
            ret->pdu.ack.eaks = NULL;
        }

        if ((ret->flags & F_NUL) && ret->dlen) {
            return NULL;
        }

        if (ret->dlen > 0) {
            guint8* data;
            data = wmem_alloc(wmem_packet_scope(),sizeof(guint8) * ret->dlen + 1);

            int i;
            for (i = 0; i < ret->dlen; i++) {
                data[i] = tvb_get_guint8(tvb,offset);
                offset++;
            }
            data[ret->dlen] = 0;
        }
        return ret;
    }

    /* Parse RST PDU */
    if ((ret->flags & M_PDU_RST) == F_RST) {
        ret->pdu.rst.rc = tvb_get_guint8(tvb,offset);
        offset++;
        return ret;
    }
    return NULL;
}

static gboolean
dissect_cattp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    cattp_pck* pck = parse_cattp_packet(tvb);

    if (pck == NULL) {
        return FALSE;
    }

    dissect_cattp(tvb,pinfo,tree);
    return TRUE;
}

static guint32
dissect_cattp_flags(tvbuff_t *tvb, proto_tree *cattp_tree, guint32 offset, cattp_pck *pck)
{
    proto_item *flags, *flag_tree;
    guint8 bit_offset;

    flags = proto_tree_add_uint_format_value(cattp_tree, hf_cattp_flags, tvb, offset, 1, pck->flags,"0x%X", pck->flags);

    flag_tree = proto_item_add_subtree(flags, ett_cattp_flags);

    bit_offset = 0;

    proto_tree_add_bits_item(flag_tree, hf_cattp_flag_syn, tvb,bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    proto_tree_add_bits_item(flag_tree, hf_cattp_flag_ack, tvb,bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    proto_tree_add_bits_item(flag_tree, hf_cattp_flag_eak, tvb,bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    proto_tree_add_bits_item(flag_tree, hf_cattp_flag_rst, tvb,bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    proto_tree_add_bits_item(flag_tree, hf_cattp_flag_nul, tvb,bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    proto_tree_add_bits_item(flag_tree, hf_cattp_flag_seg, tvb,bit_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_uint_format_value(flag_tree, hf_cattp_version, tvb,offset, 1,
                                     pck->version,"%u", pck->version);

    offset += 4; /* skip RFU and header len */
    return offset;
}

static guint32
dissect_cattp_synpdu(tvbuff_t *tvb, proto_tree *cattp_tree, guint32 offset, cattp_pck *pck)
{
    proto_item *idi, *id_tree;

    proto_tree_add_uint_format_value(cattp_tree, hf_cattp_maxpdu, tvb, offset, 2,
                                     pck->pdu.syn.maxpdu,
                                     "%u", pck->pdu.syn.maxpdu);
    offset += 2;

    proto_tree_add_uint_format_value(cattp_tree, hf_cattp_maxsdu, tvb, offset,2,
                                     pck->pdu.syn.maxsdu, "%u", pck->pdu.syn.maxsdu);
    offset += 2;

    idi = proto_tree_add_uint_format_value(cattp_tree, hf_cattp_idlen, tvb, offset, 1,
                                           pck->pdu.syn.idlen, "%u", pck->pdu.syn.idlen);
    offset++;

    id_tree = proto_item_add_subtree(idi, ett_cattp_id);

    if (pck->pdu.syn.idlen > 0) {
        wmem_strbuf_t *buf;
        int i;

        buf = wmem_strbuf_new(wmem_packet_scope(), "");

        /* Optional code. Checks whether identification field may be an ICCID.
         * It has to be considered to move this logic to another layer / dissector.
         * However it is common to send ICCID as Identification for OTA download. */
        if ((pck->pdu.syn.idlen <= 10 || pck->pdu.syn.idlen >= 9) && ICCID_PREFIX == pck->pdu.syn.id[0]) {
            /* switch nibbles */
            for (i = 0; i < pck->pdu.syn.idlen; i++) {
                guint8 c, n;

                c = pck->pdu.syn.id[i];
                n = ((c & 0xF0) >> 4) + ((c & 0x0F) << 4);
                wmem_strbuf_append_printf(buf,"%02X",n);
            }

            proto_tree_add_bytes_format_value(id_tree, hf_cattp_identification, tvb, offset,
                                              pck->pdu.syn.idlen, pck->pdu.syn.id,
                                              "%s (ICCID)", wmem_strbuf_get_str(buf));
            offset += pck->pdu.syn.idlen;
        } else {
            for (i = 0; i < pck->pdu.syn.idlen && i < CATTP_MAX_IDLEN_DISPLAY; i++) {
                wmem_strbuf_append_printf(buf,"%02X",pck->pdu.syn.id[i]);
            }

            if (i >= CATTP_MAX_IDLEN_DISPLAY) {
                wmem_strbuf_append_printf(buf,"... [%u bytes more]", pck->pdu.syn.idlen - i);
            }

            proto_tree_add_bytes_format_value(id_tree, hf_cattp_identification, tvb, offset, pck->pdu.syn.idlen,
                                              pck->pdu.syn.id, "%s", wmem_strbuf_get_str(buf));
            offset += pck->pdu.syn.idlen;
        }
    }
    return offset;
}

static guint32
dissect_cattp_eakpdu(tvbuff_t *tvb, proto_tree *cattp_tree, guint32 offset, cattp_pck *pck)
{
    proto_item *eaki;
    eaki = proto_tree_add_uint_format_value(cattp_tree, hf_cattp_eaklen, tvb, offset, pck->pdu.ack.eak_len * 2,
                                            pck->pdu.ack.eak_len, "%u PDUs",pck->pdu.ack.eak_len);

    if (pck->pdu.ack.eak_len > 0) {
        proto_item *eak_tree;
        int i;

        eak_tree = proto_item_add_subtree(eaki,ett_cattp_eaks);

        for (i = 0; i < pck->pdu.ack.eak_len && i < CATTP_MAX_EAK_DISPLAY; i++) {
	    if (i == (CATTP_MAX_EAK_DISPLAY - 1) && pck->pdu.ack.eak_len > CATTP_MAX_EAK_DISPLAY) {
               proto_tree_add_uint_format_value(eak_tree, hf_cattp_eaks, tvb, offset, pck->hlen - offset,
                                             pck->pdu.ack.eaks[i], "%u [ %u remaining EAK, max display count of %u reached ]",
					     pck->pdu.ack.eaks[i], pck->pdu.ack.eak_len - (i+1),CATTP_MAX_EAK_DISPLAY);
                offset = pck->hlen;
	    } else {
                proto_tree_add_uint_format_value(eak_tree, hf_cattp_eaks, tvb, offset, 2,
                                             pck->pdu.ack.eaks[i], "%u", pck->pdu.ack.eaks[i]);
                offset += 2;
	    }
        }
    }
    return offset;
}

static void
dissect_cattp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    cattp_pck* pck;

    pck = parse_cattp_packet(tvb);
    if (pck == NULL) {
        return;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDP CAT-TP");

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    col_add_fstr(pinfo->cinfo,COL_INFO,"%u > %u ",pck->srcport,pck->dstport);
    if ((pck->flags & M_PDU_SYN) == F_SYN)
        col_append_fstr(pinfo->cinfo,COL_INFO,"[SYN PDU] IdLen=%u ",pck->pdu.syn.idlen);
    else if ((pck->flags & M_PDU_ACK) == F_ACK)
        col_append_fstr(pinfo->cinfo,COL_INFO,"[ACK PDU] ");
    else if ((pck->flags & M_PDU_RST) == F_RST)
        col_append_fstr(pinfo->cinfo,COL_INFO,"[RST PDU] Reason=\"%s\" ",cattp_reset_reason_code(pck->pdu.rst.rc));



    col_append_fstr(pinfo->cinfo,COL_INFO,"Flags=0x%02X Ack=%u Seq=%u WSize=%u ",pck->flags,pck->ackno, pck->seqno, pck->wsize);
    if (pck->dlen > 0)
        col_append_fstr(pinfo->cinfo,COL_INFO,"DataLen=%u ",pck->dlen);

    if (pck->flags & F_EAK)
        col_append_fstr(pinfo->cinfo,COL_INFO,"EAKs=%u ",pck->pdu.ack.eak_len);

    if (tree) { /* we are being asked for details */
        proto_item *ti, *cattp_tree;
        guint32 offset;

        ti = proto_tree_add_protocol_format(tree, proto_cattp, tvb, 0, pck->hlen,
                                            "Card Application Toolkit Transport Protocol v%u, Src Port: %u, Dst Port: %u)",
                                            pck->version,pck->srcport, pck->dstport);

        cattp_tree = proto_item_add_subtree(ti, ett_cattp);

        /* render flags tree */
        offset = dissect_cattp_flags(tvb,cattp_tree,0,pck);

        /* Parse cattp source port. */
        proto_tree_add_uint_format_value(cattp_tree, hf_cattp_srcport, tvb, offset, 2,
                                         pck->srcport,"%u", pck->srcport);
        offset += 2;

        /* Parse cattp destination port. */
        proto_tree_add_uint_format_value(cattp_tree, hf_cattp_dstport, tvb, offset, 2,
                                         pck->dstport,"%u", pck->dstport);
        offset += 2;

        /* Parse length of payload. */
        proto_tree_add_uint_format_value(cattp_tree, hf_cattp_datalen, tvb, offset, 2,
                                         pck->dlen,"%u", pck->dlen);
        offset += 2;

        /* Parse sequence number. */
        proto_tree_add_uint_format_value(cattp_tree, hf_cattp_seq, tvb, offset, 2,
                                         pck->seqno,"%u", pck->seqno);
        offset += 2;

        /* Parse acknowledgement number. */
        proto_tree_add_uint_format_value(cattp_tree, hf_cattp_ack, tvb, offset, 2,
                                         pck->ackno,"%u", pck->ackno);
        offset += 2;

        /* Parse window size. */
        proto_tree_add_uint_format_value(cattp_tree, hf_cattp_windowsize, tvb, offset, 2,
                                         pck->wsize,"%u", pck->wsize);
        offset += 2;

        gushort computed_chksum;
        vec_t cksum_vec[1];
        int header_offset = 0;
        guint cksum_data_len;
        cksum_data_len = pck->hlen + pck->dlen;
        if (!cattp_check_checksum) {
            /* We have turned checksum checking off; we do NOT checksum it. */
            proto_tree_add_uint_format_value(cattp_tree, hf_cattp_checksum, tvb, offset, 2,
                                             pck->chksum,"0x%X [validation disabled]", pck->chksum);
        } else {
            /* We haven't turned checksum checking off; checksum it. */

            /* Unlike TCP, CATTP does not make use of a pseudo-header for checksum */
            SET_CKSUM_VEC_TVB(cksum_vec[0], tvb, header_offset, cksum_data_len);
            computed_chksum = in_cksum(cksum_vec, 1);

            if (computed_chksum == 0) {
                /* Checksum is valid */
                proto_tree_add_uint_format_value(cattp_tree, hf_cattp_checksum, tvb, offset, 2,
                                                 pck->chksum,"0x%X [validated]", pck->chksum);
            } else {
                /* Checksum is invalid. Let's compute the expected checksum, based on the data we have */
                gushort expected_cksum;
                expected_cksum = expected_chksum(pck->chksum, computed_chksum);
                proto_tree_add_uint_format_value(cattp_tree, hf_cattp_checksum, tvb, offset, 2, pck->chksum,
                                                 "0x%X [incorrect, correct: 0x%X]", pck->chksum, expected_cksum);
            }
        } /* End of checksum code */

        offset += 2;

        if (pck->syn)
            offset = dissect_cattp_synpdu(tvb,cattp_tree,offset,pck);
        else if (pck->eak)
            offset = dissect_cattp_eakpdu(tvb,cattp_tree,offset,pck);
        else if (pck->rst) {
            proto_tree_add_uint_format_value(cattp_tree, hf_cattp_rc, tvb, offset, 1, pck->pdu.rst.rc,
                                             "%u (\"%s\")", pck->pdu.rst.rc,cattp_reset_reason_code(pck->pdu.rst.rc));
            offset++;
        } /* for other PDU types nothing special to be displayed in detail tree. */

        /*TODO: check whether to call heuristic dissectors .*/
        if (pck->dlen > 0) { /* Call generic data handle if data exists. */
            guint32 len,reported_len;
            len = tvb_captured_length_remaining(tvb, offset);
            reported_len = tvb_reported_length_remaining(tvb, offset);
            tvb = tvb_new_subset(tvb, offset, len, reported_len);
            call_dissector(data_handle,tvb, pinfo, tree);
        }
    }
}

static gushort 
expected_chksum(gushort packet_chksum, gushort computed_chksum)
{
    gushort expected_sum;
    expected_sum = packet_chksum;
    expected_sum += g_ntohs(computed_chksum);
    expected_sum = (expected_sum & 0xFFFF) + (expected_sum >> 16);
    expected_sum = (expected_sum & 0xFFFF) + (expected_sum >> 16);
    return expected_sum;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=false:
 */
