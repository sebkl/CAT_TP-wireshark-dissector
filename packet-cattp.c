/* packet-cattp.
 * Routines for packet dissection of
 *      ETSI TS 102 127 v6.13.0  (Release 6 / 2009-0r45)
 * Copyright 2014-2014 by Sebastian Kloeppel <sebastian@kloeppel.mobi>
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
#include <string.h>

#define CATTP_DEBUG

#ifdef CATTP_DEBUG
#include <stdio.h>
#define LOGF(...) printf(__VA_ARGS__)
#endif

#define CATTP_HBLEN 18

//Function to register the dissector, called by plugin infrastructure.
void proto_register_cattp();

//Handoff
void proto_reg_handoff_cattp();

//The actual dissection
static void dissect_cattp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
//The heuristic dissector function checks if the UDP packet may be a cattp packet
static gboolean dissect_cattp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

static int proto_cattp = -1;
static guint gcattp_port = 6004;

void proto_register_cattp(void) {
	proto_cattp = proto_register_protocol (
		"ETSI CAT-TP",	/* name */
		"CAT-TP etsi",	/* short name */
		"cattp"		/* abbrev */
	);
	LOGF("Registered cattp dissector: %d\n",proto_cattp);
}

void proto_reg_handoff_cattp(void) {
	static dissector_handle_t cattp_handle;

	// Create dissector handle and 
	cattp_handle = create_dissector_handle(dissect_cattp, proto_cattp);

	dissector_add_uint("udp.port", gcattp_port, cattp_handle);
	heur_dissector_add("udp",dissect_cattp_heur,proto_cattp);

	LOGF("Handoff cattp dissector.\n");
}

typedef struct {
	gboolean syn;
	gboolean ack;
	gboolean eak;
	gboolean rst;
	gboolean nul;
	gboolean seg;
	guint8 version;
	gushort rfu;
	guint8 hlen;
	gushort srcport;
	gushort dstport;
	gushort dlen;
	gushort synno;
	gushort ackno;
	gushort wsize;
	gushort chksum;
	guint16 p_len;
	guint8* payload;
} cattp_pck;

static cattp_pck* parse_cattp_packet(tvbuff_t *tvb) {
	cattp_pck* ret = wmem_alloc(wmem_packet_scope(),sizeof(cattp_pck));

	//Ceck if the standard header fits in.
	gulong len = tvb_captured_length(tvb);
	if (len < CATTP_HBLEN) {
		//this is not a vallid CATTP packet
		return NULL;
	}

	// Parse the header.
	int offset = 0;
	guint8 fb = tvb_get_guint8(tvb,offset); offset++;

	ret->syn = (fb & 0x80) > 0;
	ret->ack = (fb & 0x40) > 0;
	ret->eak = (fb & 0x20) > 0;
	ret->rst = (fb & 0x10) > 0;
	ret->nul = (fb & 0x08) > 0;
	ret->seg = (fb & 0x04) > 0;
	ret->version = fb & 0x03;

	ret->rfu = tvb_get_ntohs(tvb,offset); offset+=2;
	ret->hlen = tvb_get_guint8(tvb,offset); offset++;
	ret->srcport = tvb_get_ntohs(tvb,offset); offset+=2;
	ret->dstport = tvb_get_ntohs(tvb,offset); offset+=2;
	ret->dlen = tvb_get_ntohs(tvb,offset); offset+=2;
	ret->synno = tvb_get_ntohs(tvb,offset); offset+=2;
	ret->ackno = tvb_get_ntohs(tvb,offset); offset+=2;
	ret->wsize = tvb_get_ntohs(tvb,offset); offset+=2;
	ret->chksum = tvb_get_ntohs(tvb,offset); offset+=2;

	//Verify the header:
	int tl = ret->hlen + ret->dlen;
	if (tl != len) {
		/* Invalid header/data len -> abort */
		return NULL;
	}
	
	return ret;
}

static gboolean dissect_cattp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
	LOGF("DISSECT_HEUR\n");

	cattp_pck* pck = parse_cattp_packet(tvb);

	if (pck == NULL) {
		LOGF("Not a cattp packet\n");
		return FALSE;
	}


	/*
	10 RST
	40 ACK
	80 SYN
	c0 SYN ACK
	48 ACK NUL
	60 ACK EAK
      */

	dissect_cattp(tvb,pinfo,tree);
	return TRUE;
}

static void dissect_cattp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	LOGF("DISSECT\n");
	cattp_pck* pck = parse_cattp_packet(tvb);
	//LOGF("syn:%d ack:%d eak:%d rst:%d nul:%d seg:%d version:%d hlen:%d",pck->syn,pck->ack,pck->eak,pck->rst,pck->nul,pck->seg,pck->version,pck->hlen);

	if (pck == NULL) {
		LOGF("Not a cattp packet.\n");
		return;
	}

	LOGF("S:%d A:%d E:%d R:%d N:%d SEG:%d version:%d rfu: %X hlen:%d sport:%d dport:%d dlen:%d\n",pck->syn,pck->ack,pck->eak,pck->rst,pck->nul,pck->seg,pck->version,pck->rfu,pck->hlen,pck->srcport, pck->dstport, pck->dlen);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "cattp");

	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);


	if (tree) { /* we are being asked for details */
		proto_item *ti = NULL;
		ti = proto_tree_add_item(tree, proto_cattp, tvb, 0, -1, ENC_NA);
	}

	/* tcp reassembling is done by HTTP dissector. */
	//static tvbuff_t	*next_tvb = NULL;

	/*

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "HTTP/OBML");
	}

	if (check_col(pinfo->cinfo,COL_INFO)) {
		col_clear(pinfo->cinfo,COL_INFO);
	}

	guint8* data = (guint8*) g_memdup((*os)->output,(*os)->oSize);
	
	next_tvb = tvb_new_real_data((guint8*) data,(*os)->oSize,(*os)->oSize);
	tvb_set_child_real_data_tvbuff(tvb, next_tvb);
	add_new_data_source(pinfo, next_tvb, "Decoded OBML Data");

	if (tree) {
		proto_item *ti = NULL;
		ti = proto_tree_add_item(tree, proto_cattp, next_tvb, 0, (*os)->oSize, TRUE);
	} 
	*/
	wmem_free(wmem_packet_scope(),pck);
}
