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


void launch_stm(void *unused)
{
    u64 msr_content = 0;
    /* int rc; */
    u64 eax_reg;
    unsigned int cpu;

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
    spin_lock(&cntr_lock);
    while ( number_ap < ((int)num_online_cpus() - 1) )
    {
        spin_unlock(&cntr_lock);
        spin_lock(&cntr_lock);
    }
    spin_unlock(&cntr_lock);

    return;
}
