/* Wireshark - Network traffic analyzer
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"
#include <epan/packet.h>

#define AFIT_ENCAP_UDP_PORT 52002

static gint ett_afit_encap = -1;
static gint proto_afit_encap = -1;
static gint hf_afit_encap_type_ext = -1;
static gint hf_afit_zwave_channel_type = -1;
static gint hf_afit_zwave_preamble_count = -1;
static gint hf_afit_zwave_symbol_count = -1;

static dissector_handle_t data_handle;

static dissector_table_t afit_encap_dissector_table;

static const value_string afit_encap_packet_type_names[] = {
	{	0x1, "Scapy Radio Zwave" },
	{	0x2, "Scapy Radio Zigbee" },
	{	0x3, "AFIT Sniffer Zwave" }
};  

static const value_string afit_zwave_channel_type_names[] = {
	{	0x1, "Zwave Channel Config 1, Rate 2" },
	{	0x2, "Zwave Channel Config 2, Rate 1" },
	{	0x3, "Zwave Channel Config 2, Rate 2" },
	{	0x4, "Zwave Channel Config 2, Rate 3" },
	{   0x5, "Zwave Channel Config 3, Rate 3" }
};

static int dissect_afit_encap (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	int type = tvb_get_guint8 (tvb, 0);
	tvbuff_t *next_tvb;

	col_clear (pinfo->cinfo, COL_INFO);
	col_add_fstr (pinfo->cinfo,COL_INFO, ": %s len=(%i)", val_to_str(type, afit_encap_packet_type_names, "Unknown (0x%02x)"), tvb_reported_length(tvb));

	if (tree)
	{
		proto_item* ti = NULL;
		proto_tree* afit_encap_tree = NULL;

		ti = proto_tree_add_item (tree, proto_afit_encap, tvb, 0, -1, ENC_NA);
		proto_item_append_text (ti, ": %s len=(%i)", val_to_str(type, afit_encap_packet_type_names, "Unknown (0x%02x)"), tvb_reported_length(tvb));
		
		afit_encap_tree = proto_item_add_subtree (ti, ett_afit_encap);
		proto_tree_add_item (afit_encap_tree, hf_afit_encap_type_ext, tvb, offset, 1, ENC_BIG_ENDIAN);

		if (type == 0x3)
		{
			offset++;
			proto_tree_add_item (afit_encap_tree, hf_afit_zwave_channel_type, tvb, offset,1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item (afit_encap_tree, hf_afit_zwave_preamble_count, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			proto_tree_add_item (afit_encap_tree, hf_afit_zwave_symbol_count, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset +=5; // Add 32bit int + 1 byte of padding
		}
		else
		{
			offset += 8; // The remaining bytes of this header are unused.
		}

		next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb,offset), tvb_reported_length(tvb));
		
		if (!dissector_try_uint(afit_encap_dissector_table, type, next_tvb, pinfo, tree))
		{
			call_dissector(data_handle, next_tvb, pinfo, tree);
		}

	}
	return tvb_captured_length(tvb);
}

void
proto_register_afit_encap (void)
{
	static hf_register_info hf[] = {
		{ &hf_afit_encap_type_ext,
			{ "Encapsulation Type", "afit_encap.encap_type",
				 FT_UINT8, BASE_DEC, VALS (afit_encap_packet_type_names),
			 	0x0, NULL, HFILL
			}
		},

		{ &hf_afit_zwave_channel_type,
			{ "Channel CFG & Rate",
				"afit_encap.channel_config", FT_UINT8, BASE_DEC,
				VALS (afit_zwave_channel_type_names), 0x0, NULL, HFILL
			}
		},

		{ &hf_afit_zwave_preamble_count,
			{  "Preamble Length",
				"afit_encap.preamble_count", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},

		{ &hf_afit_zwave_symbol_count,
			{	"Symbol Count Index",
				"afit_encap.symbol_count", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		}

	};

	static gint *ett[] = {
			&ett_afit_encap
		
	};


	proto_afit_encap = proto_register_protocol (
			"AFIT Encapsulation",
			"afit_encap",
			"afit_encap"
	);

	
  	afit_encap_dissector_table = register_dissector_table("afit_encap.encap_type", "Temporary Encapsulation Type for ZWAVE dissector", FT_UINT8, BASE_DEC, DISSECTOR_TABLE_NOT_ALLOW_DUPLICATE);	
	proto_register_field_array (proto_afit_encap, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_afit_encap (void)
{
	static dissector_handle_t afit_encap_handle;
 	
	data_handle = find_dissector("data");
    afit_encap_handle = create_dissector_handle (dissect_afit_encap, proto_afit_encap);
	dissector_add_uint("udp.port", AFIT_ENCAP_UDP_PORT, afit_encap_handle);

}
