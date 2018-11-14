/*
 * dual_monitor_mode.c: Interface to Intel's SMM Transfer Monitor (STM)
 *
 * Tejaswini Vibhute - <tejaswiniav@gmail.com> - Portland State University
 *
 *  This program contains functions that opt-in to STM and create STM policies
 *  to protect Xen's critical resources.
 *
 */

#include <asm/dual_monitor_mode.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>

static DEFINE_PER_CPU(paddr_t, temp_vmcs);
static DEFINE_SPINLOCK(cntr_lock);
volatile bool_t stmbspdone = false;
volatile bool_t is_stm = false;
static int number_ap = 0;

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

void manage_vmcs_database(uint64_t vmcsptr, uint32_t add_remove)
{
    STM_VMCS_DATABASE_REQUEST *vmcsdb_request = NULL;
    void *requestlist;
    uint32_t eax_reg = 0;
    uint32_t ebx_reg = 0;
    uint32_t ecx_reg = 0;

    printk("STM: Invoking Operation on VMCS Database\n");
    if( (requestlist = alloc_xenheap_pages(1, 0)) == NULL )
    {
        printk("STM: Failed to allocate resource page.\n");
        return;
    }

    vmcsdb_request = (STM_VMCS_DATABASE_REQUEST*)requestlist;
    vmcsdb_request->VmcsPhysPointer = vmcsptr;
    vmcsdb_request->DomainType = DOMAIN_UNPROTECTED;
    vmcsdb_request->XStatePolicy = XSTATE_READONLY;
    vmcsdb_request->DegradationPolicy = DOMAIN_UNPROTECTED;
    vmcsdb_request->AddOrRemove = add_remove;
    vmcsdb_request->Reserved1 = 0x0;

    ebx_reg = (uint64_t)__pa((unsigned long)requestlist);
    ecx_reg = ((uint64_t)__pa((unsigned long)requestlist)) >> 32;

    asm volatile(
            ".byte 0x0f,0x01,0xc1\n"
            :"=a"(eax_reg)
            :"a"(STM_API_MANAGE_VMCS_DATABASE), "b"(ebx_reg), "c"(ecx_reg)
            );

    if(eax_reg != STM_SUCCESS)
        printk("STM: Operation on VMCS Database failed with error: %lx\n", \
                (unsigned long)eax_reg);
    free_xenheap_page(requestlist);
    clear_page(requestlist);
    return;
}

void protect_resources(void)
{
    void *resourcelist;
    STM_RSC *xenresources;
    uint32_t eax_reg = STM_API_PROTECT_RESOURCE;
    uint32_t ebx_reg = 0;
    uint32_t ecx_reg = 0;
    int page_index = 0;

    printk("STM: Protecting Xen Resources\n");
    if( (resourcelist = alloc_xenheap_pages(2, 0)) == NULL )
    {
        printk("STM: Failed to allocate resource page.\n");
        return;
    }

    xenresources = (STM_RSC*)resourcelist;

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

    ebx_reg = (uint64_t)__pa((unsigned long)resourcelist + \
                    page_index*PAGE_SIZE);
    ecx_reg = ((uint64_t)__pa((unsigned long)resourcelist + \
                    page_index*PAGE_SIZE)) >> 32;

    asm volatile(
            ".byte 0x0f,0x01,0xc1\n"
            :"=a"(eax_reg)
            :"a"(eax_reg), "b"(ebx_reg), "c"(ecx_reg)
            :"memory"
            );

    if(eax_reg != STM_SUCCESS)
    {
        printk("STM: Protect Resource failed with error: %d\n", \
                xenresources->Msr.Hdr.ReturnStatus);
        free_xenheap_page(resourcelist);
        return;
    }
    clear_page(resourcelist);
    free_xenheap_page(resourcelist);
    return;
}

uint32_t get_bios_resource(STM_RSC *resource)
{
    void *resourcelist;
    uint32_t eax_reg = 0;
    uint32_t ebx_reg = 0;
    uint32_t ecx_reg = 0;
    uint32_t edx_reg = 0;
    int page_index = 0;

    printk("STM: Obtaining BIOS resource list\n");

    if ( (resourcelist = alloc_xenheap_pages(2, 0)) == NULL )
    {
        printk("STM: Failed to allocate resource page.\n");
        return -1;
    }

    eax_reg = STM_API_GET_BIOS_RESOURCES;

    ebx_reg = (uint64_t)__pa((struct page_info*)resourcelist + \
            page_index*PAGE_SIZE);
    ecx_reg = ((uint64_t)__pa((struct page_info*)resourcelist + \
                page_index*PAGE_SIZE)) >> 32;
    edx_reg = page_index;

    asm volatile(
            ".byte 0x0f,0x01,0xc1\n"
            :"=a"(eax_reg)
            :"a"(eax_reg), "b"(ebx_reg), "c"(ecx_reg), "d"(edx_reg)
            :"memory"
            );
    if(eax_reg != STM_SUCCESS)
    {
        printk("STM: Get Bios Resource Failed with error: %lu\n", \
                    (unsigned long)eax_reg);
        free_xenheap_page(resourcelist);
        return -1;
    }

    resource = (STM_RSC*)resourcelist;
    free_xenheap_page(resourcelist);
    return edx_reg;
}

void launch_stm(void *unused)
{
    u64 msr_content = 0;
    u64 eax_reg;
    unsigned int cpu;
    void *resource = NULL;
    uint32_t ret;

    /* Consult MSR IA32_FEATURE_CONTROL (0x3A) to find out if
     * dual-monitor-mode is supported.
     * bit 0: lock bit
     * bit 1: enable VMXON in SMX operation
     * bit 2: enable VMXON outside of SMX operation
     */
    rdmsr_safe(MSR_IA32_FEATURE_CONTROL, msr_content);
    if ( (msr_content & IA32_FEATURE_CONTROL_LOCK) == 0 || \
        ((msr_content & IA32_FEATURE_CONTROL_ENABLE_VMXON_INSIDE_SMX) == 0 && \
        (msr_content & IA32_FEATURE_CONTROL_ENABLE_VMXON_OUTSIDE_SMX) == 0) )
    {
        printk("STM: VMX not enabled\n");
        return;
    }

    msr_content = 0;
    /* Proceed only if support is determined. */
    rdmsr_safe(MSR_IA32_SMM_MONITOR_CTL, msr_content);
    if ( (msr_content & IA32_SMM_MONITOR_CTL_VALID) == 0 )
    {
        printk("STM: No STM opt-in from BIOS\n");
        return;
    }

    /* Allocate a temporary VMCS per CPU */
    cpu = smp_processor_id();
    printk("STM: Opt-in to STM commences on %d\n", cpu);
    per_cpu(temp_vmcs, cpu) = vmx_temp_vmcs();
    if ( !per_cpu(temp_vmcs, cpu) )
    {
        printk("STM: Failed to create VMCS\n");
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
                :"memory");

        if ( eax_reg == STM_SUCCESS )
            printk("STM: Successfully initialized STM Resources on CPU %d\n", \
                    cpu);
        else
        {
            printk("STM: Unable to initialize STM Resoucres on CPU %d\n", \
                    cpu);
            return;
        }

        /* Get Bios Resources */
        do {
            ret = get_bios_resource(resource);
        } while ( ret > 0 );

        /* Protect Xen Resources */
        protect_resources();
        /* Start STM */
        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(STM_API_START));

        if ( eax_reg == STM_SUCCESS )
            printk("STM: Opt-in succeeded on CPU %d\n", cpu);
        else
        {
            printk("STM: Unable to opt-in on CPU %d\n", cpu);
            return;
        }
        stmbspdone = true;
        spin_lock(&cntr_lock);
        while ( number_ap < ((int)num_online_cpus() - 1) )
        {
            spin_unlock(&cntr_lock);
            spin_lock(&cntr_lock);
        }
        is_stm = true;
        stmbspdone = false;
        number_ap = 0;
        spin_unlock(&cntr_lock);
    }
    else
    {
        while ( !stmbspdone ) {;}
        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(STM_API_START));

        if ( eax_reg == STM_SUCCESS )
            printk("STM: Opt-in succeeded on CPU %d\n", smp_processor_id());
        else
        {
            printk("STM: Unable to opt-in on CPU %d\n", smp_processor_id());
            return;
        }

        spin_lock(&cntr_lock);
        number_ap += 1;
        spin_unlock(&cntr_lock);
    }
    return;
}

void teardown_stm(void *unused)
{
    uint32_t eax_reg = 0;

    /* Teardown STM only if it has been previously enabled */
    if ( !is_stm )
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

        if(eax_reg == STM_SUCCESS)
            printk("STM: STM shutdown on CPU %d\n", smp_processor_id());
        else
        {
            printk("STM: Failed to shutdown STM on CPU %d with error: \
                    %032x\n", smp_processor_id(), eax_reg);
            return;
        }
        stmbspdone = true;
    }
    else
    {
        while ( !stmbspdone ) {;}
        /* Teardown STM */
        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(STM_API_STOP));

        if ( eax_reg == STM_SUCCESS )
            printk("STM: STM shutdown on CPU %d\n", smp_processor_id());
        else
        {
            printk("STM: Failed to shutdown STM on CPU %d with error: \
                    %032x\n", smp_processor_id(), eax_reg);
            return;
        }
     }
    return;
}

