/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_WUS_MaxDurationFactor_NB_r15_H_
#define	_WUS_MaxDurationFactor_NB_r15_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum WUS_MaxDurationFactor_NB_r15 {
	WUS_MaxDurationFactor_NB_r15_one128th	= 0,
	WUS_MaxDurationFactor_NB_r15_one64th	= 1,
	WUS_MaxDurationFactor_NB_r15_one32th	= 2,
	WUS_MaxDurationFactor_NB_r15_one16th	= 3,
	WUS_MaxDurationFactor_NB_r15_oneEighth	= 4,
	WUS_MaxDurationFactor_NB_r15_oneQuarter	= 5,
	WUS_MaxDurationFactor_NB_r15_oneHalf	= 6
} e_WUS_MaxDurationFactor_NB_r15;

/* WUS-MaxDurationFactor-NB-r15 */
typedef long	 WUS_MaxDurationFactor_NB_r15_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_WUS_MaxDurationFactor_NB_r15_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_WUS_MaxDurationFactor_NB_r15;
extern const asn_INTEGER_specifics_t asn_SPC_WUS_MaxDurationFactor_NB_r15_specs_1;
asn_struct_free_f WUS_MaxDurationFactor_NB_r15_free;
asn_struct_print_f WUS_MaxDurationFactor_NB_r15_print;
asn_constr_check_f WUS_MaxDurationFactor_NB_r15_constraint;
ber_type_decoder_f WUS_MaxDurationFactor_NB_r15_decode_ber;
der_type_encoder_f WUS_MaxDurationFactor_NB_r15_encode_der;
xer_type_decoder_f WUS_MaxDurationFactor_NB_r15_decode_xer;
xer_type_encoder_f WUS_MaxDurationFactor_NB_r15_encode_xer;
oer_type_decoder_f WUS_MaxDurationFactor_NB_r15_decode_oer;
oer_type_encoder_f WUS_MaxDurationFactor_NB_r15_encode_oer;
per_type_decoder_f WUS_MaxDurationFactor_NB_r15_decode_uper;
per_type_encoder_f WUS_MaxDurationFactor_NB_r15_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _WUS_MaxDurationFactor_NB_r15_H_ */
#include <asn_internal.h>