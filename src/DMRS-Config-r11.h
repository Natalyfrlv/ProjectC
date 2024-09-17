/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EUTRA-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_DMRS_Config_r11_H_
#define	_DMRS_Config_r11_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NULL.h>
#include <NativeInteger.h>
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DMRS_Config_r11_PR {
	DMRS_Config_r11_PR_NOTHING,	/* No components present */
	DMRS_Config_r11_PR_release,
	DMRS_Config_r11_PR_setup
} DMRS_Config_r11_PR;

/* DMRS-Config-r11 */
typedef struct DMRS_Config_r11 {
	DMRS_Config_r11_PR present;
	union DMRS_Config_r11_u {
		NULL_t	 release;
		struct DMRS_Config_r11__setup {
			long	 scramblingIdentity_r11;
			long	 scramblingIdentity2_r11;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} setup;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DMRS_Config_r11_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DMRS_Config_r11;
extern asn_CHOICE_specifics_t asn_SPC_DMRS_Config_r11_specs_1;
extern asn_TYPE_member_t asn_MBR_DMRS_Config_r11_1[2];
extern asn_per_constraints_t asn_PER_type_DMRS_Config_r11_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _DMRS_Config_r11_H_ */
#include <asn_internal.h>
