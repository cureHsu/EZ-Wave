/* packet-zwave.c
 * Routines for PROTONAME dissection
 * Copyright 201x, YOUR_NAME <YOUR_EMAIL_ADDRESS>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * (A short description of the protocol including links to specifications,
 *  detailed documentation, etc.)
 */

#include "config.h"
#include <epan/packet.h>
#include "packet-afit-encapse.h"

static int proto_zwave = -1;
static int hf_zwave_home_id = -1;
static int hf_zwave_source_id = -1;
//static int hf_zwave_frame_control = -1;
static int hf_zwave_length = -1;
static int hf_zwave_destination_id = -1;
static int hf_zwave_frame_type = -1;
static int hf_zwave_routed_flag = -1;
static int hf_zwave_ack_req_flag = -1;
static int hf_zwave_low_power_flag = -1;
static int hf_zwave_speed_mod_flag = -1;
static int hf_zwave_beam_control = -1;
static int hf_zwave_seq_nbr = -1;
static int hf_zwave_checksum = -1;
static int hf_zwave_cmd_class = -1;

const char * hf_zwave_info_fmt = " HomeId: 0x%x Src: %u Dst: %u Seq: %u Len: %u Type: %s";

static gint ett_zwave = -1;

//static gint ett_zwave_frame_control = -1;

static dissector_handle_t data_handle;



static const value_string zwave_cmd_classes[] = {
	{	 0x00	,	"No Operation"	 },
	{	 0x20	,	"Basic"	 },
	{	 0x21	,	"Controller Replication"	 },
	{	 0x22	,	"Application Status"	 },
	{	 0x25	,	"Switch Binary"	 },
	{	 0x26	,	"Switch Multilevel"	 },
	{	 0x27	,	"Switch All"	 },
	{	 0x28	,	"Switch Toggle Binary"	 },
	{	 0x29	,	"Switch Toggle Multilevel"	 },
	{	 0x2B	,	"Scene Activation"	 },
	{	 0x30	,	"Sensor Binary"	 },
	{	 0x31	,	"Sensor Multilevel" },
	{	 0x32	,	"Meter"	 },
	{	 0x33	,	"Color"	 },
	{	 0x35	,	"Meter Pulse"	 },
	{	 0x40	,	"Thermostat Mode"	 },
	{	 0x42	,	"Thermostat Operating State"	 },
	{	 0x43	,	"Thermostat Setpoint"	 },
	{	 0x44	,	"Thermostat Fan Mode"	 },
	{	 0x45	,	"Thermostat Fan State"	 },
	{	 0x46	,	"Climate Control Schedule"	 },
	{	 0x4c	,	"Door Lock Logging"	 },
	{	 0x50	,	"Basic Window Covering"	 },
	{	 0x56	,	"CRC16 Encap"	 },
	{	 0x60	,	"Multi Instance"	 },
	{	 0x62	,	"Door Lock"	 },
	{	 0x63	,	"User Code"	 },
	{	 0x70	,	"Configuration"	 },
	{	 0x71	,	"Alarm"	 },
	{	 0x72	,	"Manufacturer Specific"	 },
	{	 0x73	,	"Power Level"	 },
	{	 0x75	,	"Protection"	 },
	{	 0x76	,	"Lock"	 },
	{	 0x77	,	"Node Naming"	 },
	{	 0x80	,	"Battery"	 },
	{	 0x81	,	"Clock"	 },
	{	 0x82	,	"Hail"	 },
	{	 0x84	,	"WakeUp"	 },
	{	 0x85	,	"Association"	 },
	{	 0x86	,	"Version"	 },
	{	 0x87	,	"Indicator"	 },
	{	 0x88	,	"Proprietary"	 },
	{	 0x89	,	"Language"	 },
	{	 0x8B	,	"Time Parameters"	 },
	{	 0x8e	,	"Multi Instance Association"	 },
	{	 0x8f	,	"Multi Command"	 },
	{	 0x90	,	"Energy Production"	 },
	{	 0x98	,	"Security"	 },
	{	 0x9b	,	"Association Command Configuration"	 },
	{	 0x9c	,	"Sensor Alarm"	 }
};


// Only for channel config 1 and 2
// MSB of frame control
#define ZWAVE_FRAME_CONTROL_FRAME_TYPE_MASK 0x0F
#define ZWAVE_FRAME_CONTROL_ROUTED_FLAG 0x80
#define ZWAVE_FRAME_CONTROL_ACK_REQ_FLAG 0x40
#define ZWAVE_FRAME_CONTROL_LOW_POWER_FLAG 0x20
#define ZWAVE_FRAME_CONTROL_SPEED_MOD_FLAG 0x10

// LSB of frame control
#define ZWAVE_FRAME_CONTROL_BEAM_MASK 0x60
#define ZWAVE_FRAME_CONTROL_SEQNBR_MASK 0x0F

static const value_string zwave_frame_type_names[] = {
	{	0x1, "Singlecast Frame" },
	{	0x2, "Multicast Frame" },
	{	0x3, "Acknowledgement" },
	{	0x8, "Routed Frame" }
};

guint8 calc_checksum_tvb (tvbuff_t *tvb, size_t offset, size_t len)
{
	size_t i=0;
	guint8 sum=0xFF;
	for (i=offset;i<len-1;i++)
		sum ^= tvb_get_guint8(tvb, i);  // XOR (from ITU G9959)

	return sum;
}

static void
dissect_zwave (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	
	guint offset = 0;
	
	tvbuff_t *next_tvb;
	guint src = -1;
	guint dst = -1;
	guint type = -1;
	guint len = -1;
	guint cmd_type = -1;
	guint seq_nbr = -1;

	guint8 checksum_calc = -1;
	guint8 checksum = -1;
	guint homeid = -1;
	proto_item* ti = NULL;

	//gint16 frameControl;
//TODO: We have almost the entire header here. Consider a way to only read the tvb once and print stuff in the COL and in the tree
	homeid = tvb_get_ntohl (tvb, 0);
	src = tvb_get_guint8 (tvb, 4);
	dst = tvb_get_guint8 (tvb, 8);
	type = tvb_get_guint8 (tvb, 5) & ZWAVE_FRAME_CONTROL_FRAME_TYPE_MASK;
	seq_nbr = tvb_get_guint8 (tvb, 6) & ZWAVE_FRAME_CONTROL_SEQNBR_MASK;
	len = tvb_get_guint8 (tvb, 7);
	checksum = tvb_get_guint8 (tvb, len-1);
	
	col_set_str (pinfo->cinfo, COL_PROTOCOL, "Zwave");
	/* Clear out stuff in the info column */
	col_clear (pinfo->cinfo, COL_INFO);

	if(type == 0x1){
		cmd_type = tvb_get_guint8(tvb,9);
		col_add_fstr (pinfo->cinfo,COL_INFO, hf_zwave_info_fmt, homeid, src,dst, seq_nbr, len, val_to_str(cmd_type, zwave_cmd_classes, "Unknown (0x%02x)"));
	}else{
		col_add_fstr (pinfo->cinfo,COL_INFO, hf_zwave_info_fmt, homeid, src,dst, seq_nbr, len, val_to_str(type, zwave_frame_type_names, "Unknown (0x%02x)"));
	}
	
	//TODO: create a packet struct to reason upon.   

	if (tree)
	{
		proto_tree* zwave_tree = NULL;

		//proto_item* ti_frame_control = NULL;
		//proto_tree* frame_control_tree = NULL;

		ti = proto_tree_add_item (tree, proto_zwave, tvb, 0, -1, ENC_NA);
		if(type == 0x1){
			cmd_type = tvb_get_guint8(tvb,9);
			//col_add_fstr (pinfo->cinfo,COL_INFO, " HomeId: 0x%0x Src: 0x%x  Dst: 0x%x  Type: %s(%u) Len: %i",homeid, src,dst, val_to_str(cmd_type, zwave_cmd_classes, "Unknown (0x%02x)"), seq_nbr, len);
			proto_item_append_text (ti, hf_zwave_info_fmt, homeid, src,dst, seq_nbr, len, val_to_str(cmd_type, zwave_cmd_classes, "Unknown (0x%02x)"));
		}else{
			//col_add_fstr (pinfo->cinfo,COL_INFO, " HomeId: 0x%0x Src: 0x%x  Dst: 0x%x  Type: %s(%u) Len: %i",homeid, src,dst, val_to_str(type, zwave_frame_type_names, "Unknown (0x%02x)"), seq_nbr, len);
			proto_item_append_text (ti, hf_zwave_info_fmt, homeid, src,dst, seq_nbr, len, val_to_str(cmd_type, zwave_cmd_classes, "Unknown (0x%02x)"));
		}

//		proto_item_append_text (ti, " Src: 0x%x  Dst: 0x%x  Type: %s  Len: %i",src,dst, val_to_str(type, zwave_frame_type_names, "Unknown (0x%02x)"),len);
		zwave_tree = proto_item_add_subtree (ti, ett_zwave);
		proto_tree_add_item (zwave_tree, hf_zwave_home_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item (zwave_tree, hf_zwave_source_id, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;


		//ti_frame_control = proto_tree_add_item (zwave_tree, hf_zwave_frame_control, tvb, offset, 2, ENC_BIG_ENDIAN);
		//frame_control_tree = proto_item_add_subtree (ti_frame_control, ett_zwave_frame_control);
		//frameControl = tvb_get_ntohs(tvb, offset);

		proto_tree_add_item (zwave_tree, hf_zwave_routed_flag, tvb, offset,1, ENC_BIG_ENDIAN);
		proto_tree_add_item (zwave_tree, hf_zwave_ack_req_flag, tvb, offset,1, ENC_BIG_ENDIAN);
		proto_tree_add_item (zwave_tree, hf_zwave_low_power_flag, tvb, offset,1, ENC_BIG_ENDIAN);
		proto_tree_add_item (zwave_tree, hf_zwave_speed_mod_flag, tvb,offset,1, ENC_BIG_ENDIAN);
		proto_tree_add_item (zwave_tree, hf_zwave_frame_type, tvb, offset,1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item (zwave_tree, hf_zwave_beam_control, tvb,offset,1, ENC_BIG_ENDIAN);
		proto_tree_add_item (zwave_tree, hf_zwave_seq_nbr, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item (zwave_tree, hf_zwave_length, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item (zwave_tree, hf_zwave_destination_id, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		if (type != 0x3 )
			proto_tree_add_item (zwave_tree, hf_zwave_cmd_class, tvb, offset, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item (zwave_tree, hf_zwave_checksum, tvb, len-1, 1, ENC_BIG_ENDIAN);		
		checksum_calc = calc_checksum_tvb(tvb, 0, len);
		if (checksum_calc != checksum)
		{
				col_append_str(pinfo->cinfo, COL_INFO, " [WARNING: INVALID CHECKSUM]");
		}

		next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb,offset)-1, len-2);
		call_dissector(data_handle, next_tvb, pinfo, tree);
	
	}
	
}

void
proto_register_zwave (void)
{
 
	static hf_register_info hf[] = {
		{ &hf_zwave_home_id,
			{ "Home Id", "zwave.homeid",
			  FT_UINT32, BASE_HEX, NULL,
				0x0, NULL, HFILL
			}
		},

	{ &hf_zwave_source_id,
		{ "Source Node Id", "zwave.src_id",
			FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL
		}
	},

	{ &hf_zwave_frame_type,
		{ "Frame Type", "zwave.frame_ctrl.frame_type",
			 FT_UINT8, BASE_DEC, VALS (zwave_frame_type_names),
			 ZWAVE_FRAME_CONTROL_FRAME_TYPE_MASK, NULL, HFILL
		}
	},

	{ &hf_zwave_routed_flag,
		{ "Routed", "zwave.frame_ctrl.routed_flag",
			 FT_BOOLEAN, 8, NULL,
			 ZWAVE_FRAME_CONTROL_ROUTED_FLAG, NULL, HFILL
		}
	},

 	   { &hf_zwave_ack_req_flag,
		   { "ACK Req", "zwave.frame_ctrl.ack_req_flag",
				   FT_BOOLEAN, 8, NULL,
				   ZWAVE_FRAME_CONTROL_ACK_REQ_FLAG, NULL, HFILL
		   }
 	   },

	/*{ &hf_zwave_frame_control,
		{ "Frame Control", "zwave.frame_ctrl",
			FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
		}
	},*/ 

 	   { &hf_zwave_low_power_flag,
		   { "Low Power", "zwave.frame_ctrl.low_power_flag",
				   FT_BOOLEAN, 8, NULL,
				   ZWAVE_FRAME_CONTROL_LOW_POWER_FLAG, NULL, HFILL
		   }
 	   },

 	   { &hf_zwave_speed_mod_flag,
		   { "Speed Modified", "zwave.frame_ctrl.speed_mod_flag",
			   FT_BOOLEAN, 8, NULL,
			   ZWAVE_FRAME_CONTROL_SPEED_MOD_FLAG, NULL, HFILL
		   }
 	   },

		 { &hf_zwave_beam_control,
			 { "Beam Control", "zwave.frame_ctrl.beam_ctrl",
					FT_UINT8, BASE_DEC, NULL,
					ZWAVE_FRAME_CONTROL_BEAM_MASK, NULL, HFILL
			 }
			},

		{ &hf_zwave_seq_nbr, 
			{
			"Sequence Number", "zwave.frame_ctrl.seq_nbr",
			FT_UINT8, BASE_DEC, NULL,
			ZWAVE_FRAME_CONTROL_SEQNBR_MASK, NULL, HFILL
			}
		},

	   { &hf_zwave_length,
			   { "MPDU Length in Bytes", "zwave.len",
					   FT_UINT8, BASE_DEC, NULL,
					   0x0, NULL, HFILL
			   }
	   },

	   { &hf_zwave_destination_id,
			   { "Destination Node Id", "zwave.dst_id",
					   FT_UINT8, BASE_HEX, NULL,
					   0x0, NULL, HFILL
			   }
	   },

		{ &hf_zwave_checksum,
			{ "Checksum", "zwave.checksum",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},

		{ &hf_zwave_cmd_class,
			{
				"Command Class", "zwave.cmd_class",
				FT_UINT8, BASE_HEX, VALS(zwave_cmd_classes), 0x0, NULL, HFILL
			}
		}	

	};

	static gint *ett[] = {
			&ett_zwave
		
	};
	
	proto_zwave = proto_register_protocol (
			"ZWAVE",
			"ZWAVE",
			"zwave"
	);

	proto_register_field_array (proto_zwave, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	
}

void
proto_reg_handoff_zwave (void)
{
	static dissector_handle_t zwave_handle;


	zwave_handle = create_dissector_handle (dissect_zwave, proto_zwave);
	dissector_add_uint ("afit_encap.encap_type", 0x1, zwave_handle);
	dissector_add_uint ("afit_encap.encap_type", 0x3, zwave_handle);
		
	data_handle = find_dissector("data");
	
}


