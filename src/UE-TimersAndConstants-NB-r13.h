/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NBIOT-RRC-Definitions"
 * 	found in "rrc.asn1"
 * 	`asn1c -fcompound-names -no-gen-example -gen-PER -pdu=RRCConnectionSetup -D src`
 */

#ifndef	_UE_TimersAndConstants_NB_r13_H_
#define	_UE_TimersAndConstants_NB_r13_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeEnumerated.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UE_TimersAndConstants_NB_r13__t300_r13 {
	UE_TimersAndConstants_NB_r13__t300_r13_ms2500	= 0,
	UE_TimersAndConstants_NB_r13__t300_r13_ms4000	= 1,
	UE_TimersAndConstants_NB_r13__t300_r13_ms6000	= 2,
	UE_TimersAndConstants_NB_r13__t300_r13_ms10000	= 3,
	UE_TimersAndConstants_NB_r13__t300_r13_ms15000	= 4,
	UE_TimersAndConstants_NB_r13__t300_r13_ms25000	= 5,
	UE_TimersAndConstants_NB_r13__t300_r13_ms40000	= 6,
	UE_TimersAndConstants_NB_r13__t300_r13_ms60000	= 7
} e_UE_TimersAndConstants_NB_r13__t300_r13;
typedef enum UE_TimersAndConstants_NB_r13__t301_r13 {
	UE_TimersAndConstants_NB_r13__t301_r13_ms2500	= 0,
	UE_TimersAndConstants_NB_r13__t301_r13_ms4000	= 1,
	UE_TimersAndConstants_NB_r13__t301_r13_ms6000	= 2,
	UE_TimersAndConstants_NB_r13__t301_r13_ms10000	= 3,
	UE_TimersAndConstants_NB_r13__t301_r13_ms15000	= 4,
	UE_TimersAndConstants_NB_r13__t301_r13_ms25000	= 5,
	UE_TimersAndConstants_NB_r13__t301_r13_ms40000	= 6,
	UE_TimersAndConstants_NB_r13__t301_r13_ms60000	= 7
} e_UE_TimersAndConstants_NB_r13__t301_r13;
typedef enum UE_TimersAndConstants_NB_r13__t310_r13 {
	UE_TimersAndConstants_NB_r13__t310_r13_ms0	= 0,
	UE_TimersAndConstants_NB_r13__t310_r13_ms200	= 1,
	UE_TimersAndConstants_NB_r13__t310_r13_ms500	= 2,
	UE_TimersAndConstants_NB_r13__t310_r13_ms1000	= 3,
	UE_TimersAndConstants_NB_r13__t310_r13_ms2000	= 4,
	UE_TimersAndConstants_NB_r13__t310_r13_ms4000	= 5,
	UE_TimersAndConstants_NB_r13__t310_r13_ms8000	= 6
} e_UE_TimersAndConstants_NB_r13__t310_r13;
typedef enum UE_TimersAndConstants_NB_r13__n310_r13 {
	UE_TimersAndConstants_NB_r13__n310_r13_n1	= 0,
	UE_TimersAndConstants_NB_r13__n310_r13_n2	= 1,
	UE_TimersAndConstants_NB_r13__n310_r13_n3	= 2,
	UE_TimersAndConstants_NB_r13__n310_r13_n4	= 3,
	UE_TimersAndConstants_NB_r13__n310_r13_n6	= 4,
	UE_TimersAndConstants_NB_r13__n310_r13_n8	= 5,
	UE_TimersAndConstants_NB_r13__n310_r13_n10	= 6,
	UE_TimersAndConstants_NB_r13__n310_r13_n20	= 7
} e_UE_TimersAndConstants_NB_r13__n310_r13;
typedef enum UE_TimersAndConstants_NB_r13__t311_r13 {
	UE_TimersAndConstants_NB_r13__t311_r13_ms1000	= 0,
	UE_TimersAndConstants_NB_r13__t311_r13_ms3000	= 1,
	UE_TimersAndConstants_NB_r13__t311_r13_ms5000	= 2,
	UE_TimersAndConstants_NB_r13__t311_r13_ms10000	= 3,
	UE_TimersAndConstants_NB_r13__t311_r13_ms15000	= 4,
	UE_TimersAndConstants_NB_r13__t311_r13_ms20000	= 5,
	UE_TimersAndConstants_NB_r13__t311_r13_ms30000	= 6
} e_UE_TimersAndConstants_NB_r13__t311_r13;
typedef enum UE_TimersAndConstants_NB_r13__n311_r13 {
	UE_TimersAndConstants_NB_r13__n311_r13_n1	= 0,
	UE_TimersAndConstants_NB_r13__n311_r13_n2	= 1,
	UE_TimersAndConstants_NB_r13__n311_r13_n3	= 2,
	UE_TimersAndConstants_NB_r13__n311_r13_n4	= 3,
	UE_TimersAndConstants_NB_r13__n311_r13_n5	= 4,
	UE_TimersAndConstants_NB_r13__n311_r13_n6	= 5,
	UE_TimersAndConstants_NB_r13__n311_r13_n8	= 6,
	UE_TimersAndConstants_NB_r13__n311_r13_n10	= 7
} e_UE_TimersAndConstants_NB_r13__n311_r13;
typedef enum UE_TimersAndConstants_NB_r13__t311_v1350 {
	UE_TimersAndConstants_NB_r13__t311_v1350_ms40000	= 0,
	UE_TimersAndConstants_NB_r13__t311_v1350_ms60000	= 1,
	UE_TimersAndConstants_NB_r13__t311_v1350_ms90000	= 2,
	UE_TimersAndConstants_NB_r13__t311_v1350_ms120000	= 3
} e_UE_TimersAndConstants_NB_r13__t311_v1350;
typedef enum UE_TimersAndConstants_NB_r13__t300_v1530 {
	UE_TimersAndConstants_NB_r13__t300_v1530_ms80000	= 0,
	UE_TimersAndConstants_NB_r13__t300_v1530_ms100000	= 1,
	UE_TimersAndConstants_NB_r13__t300_v1530_ms120000	= 2
} e_UE_TimersAndConstants_NB_r13__t300_v1530;
typedef enum UE_TimersAndConstants_NB_r13__t301_v1530 {
	UE_TimersAndConstants_NB_r13__t301_v1530_ms80000	= 0,
	UE_TimersAndConstants_NB_r13__t301_v1530_ms100000	= 1,
	UE_TimersAndConstants_NB_r13__t301_v1530_ms120000	= 2
} e_UE_TimersAndConstants_NB_r13__t301_v1530;
typedef enum UE_TimersAndConstants_NB_r13__t311_v1530 {
	UE_TimersAndConstants_NB_r13__t311_v1530_ms160000	= 0,
	UE_TimersAndConstants_NB_r13__t311_v1530_ms200000	= 1
} e_UE_TimersAndConstants_NB_r13__t311_v1530;
typedef enum UE_TimersAndConstants_NB_r13__t300_r15 {
	UE_TimersAndConstants_NB_r13__t300_r15_ms6000	= 0,
	UE_TimersAndConstants_NB_r13__t300_r15_ms10000	= 1,
	UE_TimersAndConstants_NB_r13__t300_r15_ms15000	= 2,
	UE_TimersAndConstants_NB_r13__t300_r15_ms25000	= 3,
	UE_TimersAndConstants_NB_r13__t300_r15_ms40000	= 4,
	UE_TimersAndConstants_NB_r13__t300_r15_ms60000	= 5,
	UE_TimersAndConstants_NB_r13__t300_r15_ms80000	= 6,
	UE_TimersAndConstants_NB_r13__t300_r15_ms120000	= 7
} e_UE_TimersAndConstants_NB_r13__t300_r15;

/* UE-TimersAndConstants-NB-r13 */
typedef struct UE_TimersAndConstants_NB_r13 {
	long	 t300_r13;
	long	 t301_r13;
	long	 t310_r13;
	long	 n310_r13;
	long	 t311_r13;
	long	 n311_r13;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	long	*t311_v1350	/* OPTIONAL */;
	long	*t300_v1530	/* OPTIONAL */;
	long	*t301_v1530	/* OPTIONAL */;
	long	*t311_v1530	/* OPTIONAL */;
	long	*t300_r15	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_TimersAndConstants_NB_r13_t;

/* Implementation */
/* extern asn_TYPE_descriptor_t asn_DEF_t300_r13_2;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_t301_r13_11;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_t310_r13_20;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_n310_r13_28;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_t311_r13_37;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_n311_r13_45;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_t311_v1350_55;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_t300_v1530_60;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_t301_v1530_64;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_t311_v1530_68;	// (Use -fall-defs-global to expose) */
/* extern asn_TYPE_descriptor_t asn_DEF_t300_r15_71;	// (Use -fall-defs-global to expose) */
extern asn_TYPE_descriptor_t asn_DEF_UE_TimersAndConstants_NB_r13;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_TimersAndConstants_NB_r13_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_TimersAndConstants_NB_r13_1[11];

#ifdef __cplusplus
}
#endif

#endif	/* _UE_TimersAndConstants_NB_r13_H_ */
#include <asn_internal.h>
