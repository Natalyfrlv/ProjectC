/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_BandParameters_v1090_H_
#define	_BandParameters_v1090_H_


#include <asn_application.h>

/* Including external dependencies */
#include "FreqBandIndicator-v9e0.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BandParameters-v1090 */
typedef struct BandParameters_v1090 {
	FreqBandIndicator_v9e0_t	*bandEUTRA_v1090	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} BandParameters_v1090_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_BandParameters_v1090;
extern asn_SEQUENCE_specifics_t asn_SPC_BandParameters_v1090_specs_1;
extern asn_TYPE_member_t asn_MBR_BandParameters_v1090_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _BandParameters_v1090_H_ */
#include <asn_internal.h>
