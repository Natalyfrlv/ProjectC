/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_NPRACH_ConfigSIB_NB_v1530_H_
#define	_NPRACH_ConfigSIB_NB_v1530_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include "NPRACH-ParametersListTDD-NB-r15.h"
#include <constr_SEQUENCE.h>
#include "EDT-TBS-InfoList-NB-r15.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__nprach_PreambleFormat_r15 {
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__nprach_PreambleFormat_r15_fmt0	= 0,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__nprach_PreambleFormat_r15_fmt1	= 1,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__nprach_PreambleFormat_r15_fmt2	= 2,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__nprach_PreambleFormat_r15_fmt0_a	= 3,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__nprach_PreambleFormat_r15_fmt1_a	= 4
} e_NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__nprach_PreambleFormat_r15;
typedef enum NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy {
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy_n1	= 0,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy_n2	= 1,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy_n4	= 2,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy_n8	= 3,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy_n16	= 4,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy_n32	= 5,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy_n64	= 6,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy_n128	= 7,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy_n256	= 8,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy_n512	= 9,
	NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy_n1024	= 10
} e_NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15__dummy;
typedef enum NPRACH_ConfigSIB_NB_v1530__edt_Parameters_r15__edt_SmallTBS_Subset_r15 {
	NPRACH_ConfigSIB_NB_v1530__edt_Parameters_r15__edt_SmallTBS_Subset_r15_true	= 0
} e_NPRACH_ConfigSIB_NB_v1530__edt_Parameters_r15__edt_SmallTBS_Subset_r15;

/* Forward declarations */
struct NPRACH_ParametersListFmt2_NB_r15;
struct NPRACH_ParametersList_NB_r14;

/* NPRACH-ConfigSIB-NB-v1530 */
typedef struct NPRACH_ConfigSIB_NB_v1530 {
	struct NPRACH_ConfigSIB_NB_v1530__tdd_Parameters_r15 {
		long	 nprach_PreambleFormat_r15;
		long	 dummy;
		NPRACH_ParametersListTDD_NB_r15_t	 nprach_ParametersListTDD_r15;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *tdd_Parameters_r15;
	struct NPRACH_ConfigSIB_NB_v1530__fmt2_Parameters_r15 {
		struct NPRACH_ParametersListFmt2_NB_r15	*nprach_ParametersListFmt2_r15	/* OPTIONAL */;
		struct NPRACH_ParametersListFmt2_NB_r15	*nprach_ParametersListFmt2EDT_r15	/* OPTIONAL */;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *fmt2_Parameters_r15;
	struct NPRACH_ConfigSIB_NB_v1530__edt_Parameters_r15 {
		long	*edt_SmallTBS_Subset_r15	/* OPTIONAL */;
		EDT_TBS_InfoList_NB_r15_t	 edt_TBS_InfoList_r15;
		struct NPRACH_ParametersList_NB_r14	*nprach_ParametersListEDT_r15	/* OPTIONAL */;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *edt_Parameters_r15;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NPRACH_ConfigSIB_NB_v1530_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_nprach_PreambleFormat_r15_3;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_dummy_9;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_edt_SmallTBS_Subset_r15_26;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_NPRACH_ConfigSIB_NB_v1530;
extern asn_SEQUENCE_specifics_t asn_SPC_NPRACH_ConfigSIB_NB_v1530_specs_1;
extern asn_TYPE_member_t asn_MBR_NPRACH_ConfigSIB_NB_v1530_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "NPRACH-ParametersListFmt2-NB-r15.h"
#include "NPRACH-ParametersList-NB-r14.h"

#endif	/* _NPRACH_ConfigSIB_NB_v1530_H_ */
#include <asn_internal.h>
