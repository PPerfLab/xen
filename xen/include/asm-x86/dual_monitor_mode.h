/*
 * dual_monitor_mode.h: Intel's SMI Transfer Monitor related definitions
 *
 * Tejaswini Vibhute - <tejaswiniav@gmail.com> - Portland State University
 *
 */

#ifndef __ASM_X86_DUAL_MONITOR_MODE_H__
#define __ASM_X86_DUAL_MONITOR_MODE_H__

extern void launch_stm(void* unused);

#define STM_API_START                              0x00010001
#define STM_API_STOP                               0x00010002
#define STM_API_PROTECT_RESOURCE                   0x00010003
#define STM_API_UNPROTECT_RESOURCE                 0x00010004
#define STM_API_GET_BIOS_RESOURCES                 0x00010005
#define STM_API_MANAGE_VMCS_DATABASE               0x00010006
#define STM_API_INITIALIZE_PROTECTION              0x00010007
#define STM_API_MANAGE_EVENT_LOG                   0x00010008

#define STM_SUCCESS    0x00000000

#endif
