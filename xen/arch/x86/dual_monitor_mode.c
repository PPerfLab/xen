/*
 * dual_monitor_mode.c: Interface to Intel's SMM Transfer Monitor (STM)
 *
 * This program contains functions that opt-in to STM and create STM policies
 * to protect Xen's critical resources.
 *
 * Tejaswini Vibhute - <tejaswiniav@gmail.com> - Portland State University
 *
 * Copyright (C) 2018 Portland State University
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <asm/dual_monitor_mode.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>

static DEFINE_PER_CPU(paddr_t, temp_vmcs);
static DEFINE_SPINLOCK(cntr_lock);
volatile bool_t stmbsp_done = false;
/*
 * is_stm can take the following status codes. Each code represents the state of
 * STM on the current system
 * 0x00 : STM initialization not yet started
 * 0x01 : STM successfully launched on all the logical CPUs
 * 0x02 : STM launch failed
 * 0x03 : STM not supported
 */
volatile uint8_t is_stm = 0x00;
static int number_ap = 0;

/*
 * Create a temporary VMCS for the current CPU
 */
static void set_temp_vmcs(void)
{
    u64 msr_content = 0;

    __vmpclear(this_cpu(temp_vmcs));
    current->arch.hvm_vmx.vmcs_pa = this_cpu(temp_vmcs);
    vmx_vmcs_reload(current);

    rdmsr_safe(MSR_IA32_VMX_EXIT_CTLS, msr_content);
    __vmwrite(VM_EXIT_CONTROLS, msr_content);
    return;
}

/*
 * Add or Delete a VMCS entry to/from the VMCS Database in STM.
 * @param add_remove determines whether to add an entry or remove the previously
 * stored entry.
 * While adding an entry specify the Domain protection policy in the appropriate
 * fields.
 */
int manage_vmcs_database(uint64_t vmcs_ptr, uint32_t add_remove)
{
    STM_VMCS_DATABASE_REQUEST *vmcsdb_request = NULL;
    void *request_list;
    uint32_t eax_reg = 0;
    uint32_t ebx_reg = 0;
    uint32_t ecx_reg = 0;

    printk("STM: Invoking Operation on VMCS Database\n");
    if ( is_stm != 0x01 )
    {
        printk("STM: STM not enabled\n");
        return -1;
    }

    if ( (request_list = alloc_xenheap_pages(1, 0)) == NULL )
    {
        printk("STM: Failed to allocate resource page.\n");
        return -1;
    }

    vmcsdb_request = (STM_VMCS_DATABASE_REQUEST*)request_list;
    vmcsdb_request->VmcsPhysPointer = vmcs_ptr;
    vmcsdb_request->DomainType = DOMAIN_UNPROTECTED;
    vmcsdb_request->XStatePolicy = XSTATE_READONLY;
    vmcsdb_request->DegradationPolicy = DOMAIN_UNPROTECTED;
    vmcsdb_request->AddOrRemove = add_remove;
    vmcsdb_request->Reserved1 = 0x0;

    ebx_reg = (uint64_t)__pa((unsigned long)request_list);
    ecx_reg = ((uint64_t)__pa((unsigned long)request_list)) >> 32;

    asm volatile(
            ".byte 0x0f,0x01,0xc1\n"
            :"=a"(eax_reg)
            :"a"(STM_API_MANAGE_VMCS_DATABASE), "b"(ebx_reg), "c"(ecx_reg)
            );

    if ( eax_reg != STM_SUCCESS )
    {
        printk("STM: STM_API_MANAGE_VMCS_DATABASE failed with error: 0x%lx\n",\
                (unsigned long)eax_reg);

        clear_page(request_list);
        free_xenheap_page(request_list);
        return -1;
    }
    clear_page(request_list);
    free_xenheap_page(request_list);
    return 0;
}

/*
 * protect_resources creates resource protection policy profile and invokes the
 * PROTECT_RESOURCE VMCALL to apply these policy profiles over SMI handler.
 * While creating the policy profile the adopter should check for STM
 * capabilities reported after successful return from INITIALIZE_PROTECTION
 * VMCALL. The capabilities value will indicate whether the underlying STM
 * supports bit granular or whole MSR resource protection methodology. (Byte
 * granular or entire page level protection for MMIO and Memory regions.)
 * Intel's STM implementation currently only supports whole MSR or page level
 * resource protection.
 * Our sample policy profile implementation below is in synchronous with this
 * idea.
 */
int protect_resources(void)
{
    void *resource_list;
    STM_RSC *xenresources;
    uint32_t eax_reg = STM_API_PROTECT_RESOURCE;
    uint32_t ebx_reg = 0;
    uint32_t ecx_reg = 0;
    int page_index = 0;

    printk("STM: Protecting Xen Resources\n");
    if ( (resource_list = alloc_xenheap_pages(1, 0)) == NULL )
    {
        printk("STM: Failed to allocate resource page.\n");
        return -1;
    }

    xenresources = (STM_RSC*)resource_list;

    xenresources->Msr.Hdr.RscType = MACHINE_SPECIFIC_REG;
    xenresources->Msr.Hdr.Length = sizeof(STM_RSC_MSR_DESC);
    xenresources->Msr.MsrIndex = MSR_IA32_MISC_ENABLE; /* 0x1A0 */
    xenresources->Msr.WriteMask = (uint64_t) - 1;

    xenresources++;
    xenresources->Msr.Hdr.RscType = MACHINE_SPECIFIC_REG;
    xenresources->Msr.Hdr.Length = sizeof(STM_RSC_MSR_DESC);
    xenresources->Msr.MsrIndex = MSR_IA32_FEATURE_CONTROL;
    xenresources->Msr.ReadMask = (uint64_t) - 1;
    xenresources->Msr.WriteMask = (uint64_t) - 1;

    ebx_reg = (uint64_t)__pa((unsigned long)resource_list + \
                    page_index*PAGE_SIZE);
    ecx_reg = ((uint64_t)__pa((unsigned long)resource_list + \
                    page_index*PAGE_SIZE)) >> 32;

    asm volatile(
            ".byte 0x0f,0x01,0xc1\n"
            :"=a"(eax_reg)
            :"a"(eax_reg), "b"(ebx_reg), "c"(ecx_reg)
            :"memory"
            );

    if ( eax_reg != STM_SUCCESS )
    {
        printk("STM: STM_API_PROTECT_RESOURCE failed with error: 0x%lx\n", \
                (unsigned long)eax_reg);
        printk("STM: STM_API_PROTECT_RESOURCE return status in Hdr: %d\n", \
                xenresources->Msr.Hdr.ReturnStatus);
        free_xenheap_page(resource_list);
        return -1;
    }
    clear_page(resource_list);
    free_xenheap_page(resource_list);
    return 0;
}

/*
 * Obtain the BIOS resource protection list
 */
int get_bios_resource(void)
{
    void *resource_list;
    STM_RSC *resource;
    uint32_t eax_reg = 0;
    uint32_t ebx_reg = 0;
    uint32_t ecx_reg = 0;
    uint32_t edx_reg = 0;
    int page_index;

    printk("STM: Obtaining BIOS resource list.\n");

    if ( (resource_list = alloc_xenheap_pages( \
                    get_order_from_pages(MAX_RESOURCE_PAGES), 0)) == NULL )
    {
        printk("STM: Failed to allocate resource page.\n");
        return -1;
    }

    for ( page_index = 0; page_index < MAX_RESOURCE_PAGES; page_index++ )
    {
        eax_reg = STM_API_GET_BIOS_RESOURCES;

        ebx_reg = (uint64_t)__pa((struct page_info*)resource_list + \
                page_index*4096);
        ecx_reg = ((uint64_t)__pa((struct page_info*)resource_list + \
                    page_index*4096)) >> 32;
        edx_reg = page_index;

        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(eax_reg), "b"(ebx_reg), "c"(ecx_reg), "d"(edx_reg)
                :"memory"
                );

        if ( eax_reg != STM_SUCCESS )
        {
            printk("STM: STM_API_GET_BIOS_RESOURCES failed with error: \
                    0x%lx\n", (unsigned long)eax_reg);
            free_xenheap_page(resource_list);
            return -1;
        }
        resource = (STM_RSC*)((uint64_t)resource_list + page_index*4096);
        dump_stm_resource(resource);
        if ( edx_reg == 0 )
        {
            printk("STM: Reached end of BIOS Resource list\n");
            break;
        }
    }
    free_xenheap_page(resource_list);
    return 0;
}

/*
 * Opt-in to STM by invoking the INTIALIZE_PROTECTION VMCALL and STM_START
 * VMCALL. Also, obtain the BIOS resource protection list from STM and define
 * resource protection policies over MLE resources.
 */
void launch_stm(void *unused)
{
    u64 msr_content = 0;
    uint32_t eax_reg = 0;
    unsigned int cpu;
    int ret;

    /* Consult MSR IA32_VMX_BASIC to find out if STM is supported.
     * If STM is supported then bit 49 of this MSR will be set and
     * MSR IA32_SMM_MONITOR_CTL exists on such a processor.
     * Trying to access MSR IA32_SMM_MONITOR_CTL on a processor that does not
     * support STM will result in a #GP Fault.
     */
    rdmsr_safe(MSR_IA32_VMX_BASIC, msr_content);
    if ( (msr_content & VMX_BASIC_DUAL_MONITOR) == 0 )
    {
        printk("STM: STM is not supported on the processor\n");
        is_stm = 0x03;
        return;
    }

    if ( !this_cpu(vmxon) )
    {
        printk("STM: VMX is not enabled\n");
        is_stm = 0x03;
        return;
    }

    msr_content = 0;
    /* Proceed only if BIOS has opt-in to STM. */
    rdmsr_safe(MSR_IA32_SMM_MONITOR_CTL, msr_content);
    if ( (msr_content & IA32_SMM_MONITOR_CTL_VALID) == 0 )
    {
        printk("STM: No STM opt-in from BIOS\n");
        is_stm = 0x03;
        return;
    }

    /* Allocate a temporary VMCS per CPU */
    cpu = smp_processor_id();
    printk("STM: Opt-in to STM commences on %d\n", cpu);
    per_cpu(temp_vmcs, cpu) = vmx_temp_vmcs();
    if ( !per_cpu(temp_vmcs, cpu) )
    {
        printk("STM: Failed to create VMCS\n");
        is_stm = 0x02;
        return;
    }

    set_temp_vmcs();

    if ( (cpu = smp_processor_id()) == 0 )
    {
        printk("STM: Initializing STM Resources\n");
        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(STM_API_INITIALIZE_PROTECTION)
                :"cc");

        if ( eax_reg != STM_SUCCESS )
        {
            printk("STM: STM_API_INITIALIZE_PROTECTION failed with error: \
                    0x%lx\n", (unsigned long)eax_reg);
            is_stm = 0x02;
            return;
        }

        printk("STM: STM_API_INITIALIZE_PROTECTION succeeded\n");

        /* Get Bios Resources */
        ret = get_bios_resource();

        /* Protect Xen Resources */
        ret = protect_resources();
        if ( ret != 0 )
        {
            printk("STM: Exiting STM opt-in\n");
            is_stm = 0x02;
            return;
        }

        /* Start STM */
        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(STM_API_START));

        if ( eax_reg == STM_SUCCESS )
            printk("STM: STM_API_START(%d) succeeded\n", cpu);
        else
        {
            printk("STM: STM_API_START(%d) failed with error: 0x%lx\n", \
                    cpu, (unsigned long)eax_reg);
            is_stm = 0x02;
            return;
        }
        stmbsp_done = true;
        spin_lock(&cntr_lock);
        while ( number_ap < ((int)num_online_cpus() - 1) )
        {
            spin_unlock(&cntr_lock);
            spin_lock(&cntr_lock);
        }
        is_stm = 0x01;
        stmbsp_done = false;
        number_ap = 0;
        spin_unlock(&cntr_lock);
    }
    else
    {
        while ( !stmbsp_done )
        {
            if ( is_stm == 0x02 || is_stm == 0x03 )
                return;
        }

        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(STM_API_START));

        if ( eax_reg == STM_SUCCESS )
            printk("STM: STM_API_START(%d) succeeded\n", smp_processor_id());
        else
        {
            printk("STM: STM_API_START(%d) failed with error: 0x%lx\n", \
                    smp_processor_id(), (unsigned long)eax_reg);
            return;
        }

        spin_lock(&cntr_lock);
        number_ap += 1;
        spin_unlock(&cntr_lock);
    }
    return;
}

/*
 * Shutdown STM
 */
void teardown_stm(void *unused)
{
    uint32_t eax_reg = 0;

    /* Teardown STM only if it has been previously enabled */
    if ( is_stm != 0x01 )
    {
        printk("STM: STM not enabled\n");
        return;
    }

    if ( smp_processor_id() == 0 )
    {
        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(STM_API_STOP));

        if ( eax_reg == STM_SUCCESS )
            printk("STM: STM_API_STOP(%d) succeeded\n", smp_processor_id());
        else
        {
            printk("STM: STM_API_STOP(%d) failed with error: 0x%lx\n", \
                    smp_processor_id(), (unsigned long)eax_reg);
            stmbsp_done = true;
            return;
        }
        stmbsp_done = true;
    }
    else
    {
        while ( !stmbsp_done ) {;}
        /* Teardown STM */
        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(STM_API_STOP));

        if ( eax_reg == STM_SUCCESS )
            printk("STM: STM_API_STOP(%d) succeeded\n", smp_processor_id());
        else
        {
            printk("STM: STM_API_STOP(%d) failed with error: 0x%lx\n", \
                    smp_processor_id(), (unsigned long)eax_reg);
            return;
        }
    }
    return;
}

/*
 * This function dumps STM resource node header.
 */
void dump_stm_resource_header(STM_RSC *Resource)
{
    printk("XEN-STM: RscType       : %08x\n", Resource->Header.RscType);
    printk("XEN-STM: RscLength     : %04x\n", Resource->Header.Length);
    printk("XEN-STM: ReturnStatus  : %04x\n", Resource->Header.ReturnStatus);
    printk("XEN-STM: IgnoreResource: %04x\n", Resource->Header.IgnoreResource);
}

/*
 * This function dumps STM resource node.
 */
void dump_stm_resource_node(STM_RSC *Resource)
{
    uint8_t pci_index;

    switch (Resource->Header.RscType)
    {
        case END_OF_RESOURCES:
            printk("XEN-STM: END_OF_RESOURCES:\n");
            dump_stm_resource_header(Resource);
            printk("XEN-STM: ResourceListContinuation : %016lx\n", \
                Resource->End.ResourceListContinuation);
            break;
        case MEM_RANGE:
            printk("XEN-STM: MEM_RANGE:\n");
            dump_stm_resource_header(Resource);
            printk("XEN-STM: Base          : %016lx\n", Resource->Mem.Base);
            printk("XEN-STM: Length        : %016lx\n", Resource->Mem.Length);
            printk("XEN-STM: RWXAttributes : %08x\n", \
                (uint8_t)Resource->Mem.RWXAttributes);
            break;
        case IO_RANGE:
            printk("XEN-STM: IO_RANGE:\n");
            dump_stm_resource_header(Resource);
            printk("XEN-STM: Base          : %04x\n", (int)Resource->Io.Base);
            printk("XEN-STM: Length        : %04x\n", (int)Resource->Io.Length);
            break;
        case MMIO_RANGE:
            printk("XEN-STM: MMIO_RANGE:\n");
            dump_stm_resource_header(Resource);
            printk("XEN-STM: Base          : %016lx\n", Resource->Mmio.Base);
            printk("XEN-STM: Length        : %016lx\n", Resource->Mmio.Length);
            printk("XEN-STM: RWXAttributes : %08x\n", \
                (uint8_t)Resource->Mmio.RWXAttributes);
            break;
        case MACHINE_SPECIFIC_REG:
            printk("XEN-STM: MSR_RANGE:\n");
            dump_stm_resource_header(Resource);
            printk("XEN-STM: MsrIndex      : %08x\n", \
                (uint8_t)Resource->Msr.MsrIndex);
            printk("XEN-STM: KernelModeProc: %08x\n", \
                (uint8_t)Resource->Msr.KernelModeProcessing);
            printk("XEN-STM: ReadMask      : %016lx\n", Resource->Msr.ReadMask);
            printk("XEN-STM: WriteMask     : %016lx\n", \
                Resource->Msr.WriteMask);
            break;
        case PCI_CFG_RANGE:
            printk("XEN-STM: PCI_CFG_RANGE:\n");
            dump_stm_resource_header(Resource);
            printk("XEN-STM: RWAttributes  : %04x\n", \
                (int)Resource->PciCfg.RWAttributes);
            printk("XEN-STM: Base          : %04x\n", \
                (int)Resource->PciCfg.Base);
            printk("XEN-STM: Length        : %04x\n", \
                (int)Resource->PciCfg.Length);
            printk("XEN-STM: OriginatingBus: %02x\n", \
                (int)Resource->PciCfg.OriginatingBusNumber);
            printk("XEN-STM: LastNodeIndex : %02x\n", \
                (int)Resource->PciCfg.LastNodeIndex);

            for (pci_index = 0; pci_index < Resource->PciCfg.LastNodeIndex + 1;\
                   pci_index++)
            {
                printk("XEN-STM: Type          : %02x\n", \
                    (int)Resource->PciCfg.PciDevicePath[pci_index].Type);
                printk("XEN-STM: Subtype       : %02x\n", \
                    (int)Resource->PciCfg.PciDevicePath[pci_index].Subtype);
                printk("XEN-STM: Length        : %04x\n", \
                    (int)Resource->PciCfg.PciDevicePath[pci_index].Length);
                printk("XEN-STM: PciDevice     : %02x\n", \
                    (int)Resource->PciCfg.PciDevicePath[pci_index].PciDevice);
                printk("XEN-STM: PciFunction   : %02x\n", \
                    (int)Resource->PciCfg.PciDevicePath[pci_index].PciFunction);
            }
            break;
        case TRAPPED_IO_RANGE:
            printk("XEN-STM: TRAPPED_IO_RANGE:\n");
            dump_stm_resource_header(Resource);
            printk("XEN-STM: Base          : %04x\n", \
                (int)Resource->TrappedIo.Base);
            printk("XEN-STM: Length        : %04x\n", \
                (int)Resource->TrappedIo.Length);
            printk("XEN-STM: In            : %04x\n", \
                (int)Resource->TrappedIo.In);
            printk("XEN-STM: Out           : %04x\n", \
                (int)Resource->TrappedIo.Out);
            printk("XEN-STM: Api           : %04x\n", \
                (int)Resource->TrappedIo.Api);
            break;
        case ALL_RESOURCES:
            printk("XEN-STM: ALL_RESOURCES:\n");
            dump_stm_resource_header(Resource);
            break;
        case REGISTER_VIOLATION:
            printk("XEN-STM: REGISTER_VIOLATION:\n");
            dump_stm_resource_header(Resource);
            printk("XEN-STM: RegisterType  : %08x\n", \
                (uint8_t)Resource->RegisterViolation.RegisterType);
            printk("XEN-STM: ReadMask      : %016lx\n", \
                Resource->RegisterViolation.ReadMask);
            printk("XEN-STM: WriteMask     : %016lx\n", \
                Resource->RegisterViolation.WriteMask);
            break;
        default:
            dump_stm_resource_header(Resource);
            break;
    }
}

/*
 * This function dumps STM resource list.
 */
void dump_stm_resource(STM_RSC *Resource)
{
    while (Resource->Header.RscType != END_OF_RESOURCES)
    {
        dump_stm_resource_node(Resource);
        Resource = (STM_RSC *)((uint64_t)Resource + Resource->Header.Length);
    }
    /* Dump End Node */
    dump_stm_resource_node(Resource);

    if (Resource->End.ResourceListContinuation != 0)
        dump_stm_resource( \
                (STM_RSC *)(uint64_t)Resource->End.ResourceListContinuation);
}

