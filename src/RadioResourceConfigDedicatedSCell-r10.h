/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_RadioResourceConfigDedicatedSCell_r10_H_
#define	_RadioResourceConfigDedicatedSCell_r10_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BOOLEAN.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PhysicalConfigDedicatedSCell_r10;
struct MAC_MainConfigSCell_r11;
struct NAICS_AssistanceInfo_r12;
struct NeighCellsCRS_Info_r13;
struct PhysicalConfigDedicatedSCell_v1370;
struct NeighCellsCRS_Info_r15;
struct SPS_Config_v1530;

/* RadioResourceConfigDedicatedSCell-r10 */
typedef struct RadioResourceConfigDedicatedSCell_r10 {
	struct PhysicalConfigDedicatedSCell_r10	*physicalConfigDedicatedSCell_r10	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	struct MAC_MainConfigSCell_r11	*mac_MainConfigSCell_r11	/* OPTIONAL */;
	struct NAICS_AssistanceInfo_r12	*naics_Info_r12	/* OPTIONAL */;
	struct NeighCellsCRS_Info_r13	*neighCellsCRS_InfoSCell_r13	/* OPTIONAL */;
	struct PhysicalConfigDedicatedSCell_v1370	*physicalConfigDedicatedSCell_v1370	/* OPTIONAL */;
	BOOLEAN_t	*crs_IntfMitigEnabled_r15	/* OPTIONAL */;
	struct NeighCellsCRS_Info_r15	*neighCellsCRS_Info_r15	/* OPTIONAL */;
	struct SPS_Config_v1530	*sps_Config_v1530	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RadioResourceConfigDedicatedSCell_r10_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RadioResourceConfigDedicatedSCell_r10;
extern asn_SEQUENCE_specifics_t asn_SPC_RadioResourceConfigDedicatedSCell_r10_specs_1;
extern asn_TYPE_member_t asn_MBR_RadioResourceConfigDedicatedSCell_r10_1[8];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PhysicalConfigDedicatedSCell-r10.h"
#include "MAC-MainConfigSCell-r11.h"
#include "NAICS-AssistanceInfo-r12.h"
#include "NeighCellsCRS-Info-r13.h"
#include "PhysicalConfigDedicatedSCell-v1370.h"
#include "NeighCellsCRS-Info-r15.h"
#include "SPS-Config-v1530.h"

#endif	/* _RadioResourceConfigDedicatedSCell_r10_H_ */
#include <asn_internal.h>
