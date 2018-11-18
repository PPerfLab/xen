/*
 * dual_monitor_mode.h: Intel's SMI Transfer Monitor related definitions
 *
 * Tejaswini Vibhute - <tejaswiniav@gmail.com> - Portland State University
 *
 */

#ifndef __ASM_X86_DUAL_MONITOR_MODE_H__
#define __ASM_X86_DUAL_MONITOR_MODE_H__

#include <asm/hvm/io.h>

extern void launch_stm(void* unused);
void manage_vmcs_database(uint64_t vmcs_ptr, uint32_t add_remove);
extern void teardown_stm(void* unused);

/*
 * STM VMCALL Codes
 */
#define STM_API_START                              0x00010001
#define STM_API_STOP                               0x00010002
#define STM_API_PROTECT_RESOURCE                   0x00010003
#define STM_API_UNPROTECT_RESOURCE                 0x00010004
#define STM_API_GET_BIOS_RESOURCES                 0x00010005
#define STM_API_MANAGE_VMCS_DATABASE               0x00010006
#define STM_API_INITIALIZE_PROTECTION              0x00010007
#define STM_API_MANAGE_EVENT_LOG                   0x00010008

/*
 * STM Return Codes
 */
#define STM_SUCCESS    0x00000000


#define MAX_RESOURCE_PAGES 4

/*
 * STM_RESOURCE_LIST
 */
#define END_OF_RESOURCES        0
#define MEM_RANGE               1
#define IO_RANGE                2
#define MMIO_RANGE              3
#define MACHINE_SPECIFIC_REG    4
#define PCI_CFG_RANGE           5
#define TRAPPED_IO_RANGE        6
#define ALL_RESOURCES           7
#define REGISTER_VIOLATION      8
#define MAX_DESC_TYPE           8

typedef struct {
  uint32_t RscType;
  uint16_t Length;
  uint16_t ReturnStatus:1;
  uint16_t Reserved:14;
  uint16_t IgnoreResource:1;
} STM_RSC_DESC_HEADER;

typedef struct {
  STM_RSC_DESC_HEADER Hdr;
  uint64_t              ResourceListContinuation;
} STM_RSC_END;

/* byte granular Memory range support */
#define STM_RSC_BGM    0x4

typedef struct {
  STM_RSC_DESC_HEADER Hdr;
  uint64_t              Base;
  uint64_t              Length;
  uint32_t              RWXAttributes:3;
  uint32_t              Reserved:29;
  uint32_t              Reserved_2;
} STM_RSC_MEM_DESC;
#define STM_RSC_MEM_R    0x1
#define STM_RSC_MEM_W    0x2
#define STM_RSC_MEM_X    0x4

typedef struct {
  STM_RSC_DESC_HEADER Hdr;
  uint16_t              Base;
  uint16_t              Length;
  uint32_t              Reserved;
} STM_RSC_IO_DESC;

/* byte granular MMIO range support */
#define STM_RSC_BGI    0x2

typedef struct {
  STM_RSC_DESC_HEADER Hdr;
  uint64_t              Base;
  uint64_t              Length;
  uint32_t              RWXAttributes:3;
  uint32_t              Reserved:29;
  uint32_t              Reserved_2;
} STM_RSC_MMIO_DESC;
#define STM_RSC_MMIO_R    0x1
#define STM_RSC_MMIO_W    0x2
#define STM_RSC_MMIO_X    0x4

typedef struct {
  STM_RSC_DESC_HEADER Hdr;
  uint32_t              MsrIndex;
  uint32_t              KernelModeProcessing:1;
  uint32_t              Reserved:31;
  uint64_t              ReadMask;
  uint64_t              WriteMask;
} STM_RSC_MSR_DESC;

/* bit granular MSR resource support */
#define STM_RSC_MSR    0x8

typedef struct {
  uint8_t  Type;    /* must be 1, indicating Hardware Device Path */
  uint8_t  Subtype; /* must be 1, indicating PCI */
  uint16_t Length;  /* sizeof(STM_PCI_DEVICE_PATH_NODE) which is 6 */
  uint8_t  PciFunction;
  uint8_t  PciDevice;
} STM_PCI_DEVICE_PATH_NODE;

typedef struct {
  STM_RSC_DESC_HEADER       Hdr;
  uint16_t                    RWAttributes:2;
  uint16_t                    Reserved:14;
  uint16_t                    Base;
  uint16_t                    Length;
  uint8_t                     OriginatingBusNumber;
  uint8_t                     LastNodeIndex;
  STM_PCI_DEVICE_PATH_NODE  PciDevicePath[1];
/* STM_PCI_DEVICE_PATH_NODE  PciDevicePath[LastNodeIndex + 1]; */
} STM_RSC_PCI_CFG_DESC;

#define STM_RSC_PCI_CFG_R    0x1
#define STM_RSC_PCI_CFG_W    0x2

typedef struct {
  STM_RSC_DESC_HEADER Hdr;
  uint16_t              Base;
  uint16_t              Length;
  uint16_t              In:1;
  uint16_t              Out:1;
  uint16_t              Api:1;
  uint16_t              Reserved1:13;
  uint16_t              Reserved2;
} STM_RSC_TRAPPED_IO_DESC;

typedef struct {
  STM_RSC_DESC_HEADER Hdr;
} STM_RSC_ALL_RESOURCES_DESC;

typedef struct {
  STM_RSC_DESC_HEADER Hdr;
  uint32_t              RegisterType;
  uint32_t              Reserved;
  uint64_t              ReadMask;
  uint64_t              WriteMask;
} STM_REGISTER_VIOLATION_DESC;

typedef enum {
  StmRegisterCr0,
  StmRegisterCr2,
  StmRegisterCr3,
  StmRegisterCr4,
  StmRegisterCr8,
  StmRegisterMax,
} STM_REGISTER_VIOLATION_TYPE;

typedef union {
  STM_RSC_DESC_HEADER             Header;
  STM_RSC_END                     End;
  STM_RSC_MEM_DESC                Mem;
  STM_RSC_IO_DESC                 Io;
  STM_RSC_MMIO_DESC               Mmio;
  STM_RSC_MSR_DESC                Msr;
  STM_RSC_PCI_CFG_DESC            PciCfg;
  STM_RSC_TRAPPED_IO_DESC         TrappedIo;
  STM_RSC_ALL_RESOURCES_DESC      All;
  STM_REGISTER_VIOLATION_DESC     RegisterViolation;
} STM_RSC;

/*
 * VMCS database
 */
#define STM_VMCS_DATABASE_REQUEST_ADD    1
#define STM_VMCS_DATABASE_REQUEST_REMOVE 0

/* Values for DomainType
 * Intepreter of DomainType
 */
#define DOMAIN_DISALLOWED_IO_OUT (1u << 0)
#define DOMAIN_DISALLOWED_IO_IN  (1u << 1)
#define DOMAIN_INTEGRITY         (1u << 2)
#define DOMAIN_CONFIDENTIALITY   (1u << 3)

#define DOMAIN_UNPROTECTED           0x00
#define DOMAIN_INTEGRITY_PROT_OUT_IN (DOMAIN_INTEGRITY)
#define DOMAIN_FULLY_PROT_OUT_IN     (DOMAIN_CONFIDENTIALITY | \
                                        DOMAIN_INTEGRITY)
#define DOMAIN_FULLY_PROT            (DOMAIN_CONFIDENTIALITY | \
                                        DOMAIN_INTEGRITY | \
                                        DOMAIN_DISALLOWED_IO_IN | \
                                        DOMAIN_DISALLOWED_IO_OUT)

/* Values for XStatePolicy */
#define XSTATE_READWRITE      0x00
#define XSTATE_READONLY       0x01
#define XSTATE_SCRUB          0x03

typedef struct {
  uint64_t VmcsPhysPointer; /* bits 11:0 are reserved and must be 0 */
  uint32_t DomainType :4;
  uint32_t XStatePolicy :2;
  uint32_t DegradationPolicy :4;
  uint32_t Reserved1 :22; /* Must be 0 */
  uint32_t AddOrRemove;
} STM_VMCS_DATABASE_REQUEST;

#endif
