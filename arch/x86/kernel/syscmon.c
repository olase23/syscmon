/*
 * sys_call_table integrity monitor
 *
 * Copyright (C) 2019, Olaf Schmerse
 * Author : Olaf Schmerse <olase23@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <asm/asm-offsets.h>
#include <asm/cpufeature.h>
#include <asm/desc.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/syscalls.h>
#include <asm/unistd.h>
#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/linkage.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sys.h>
#include <linux/syscalls.h>

#define DEBUG 1
#define SCM_SLEEP (5 * HZ)
#define SYS_CALL_TABLE_SIZE NR_syscalls * sizeof(long)
#define SCM_PROC_BASE_NAME "syscall_monitor"

static DEFINE_SPINLOCK(log_list_lock);

static unsigned long *shadow_sys_call_tbl[SYS_CALL_TABLE_SIZE];

static struct proc_dir_entry *scm_proc_file;
static struct list_head event_log_list;
static struct task_struct *scm_task;
static struct module *kmodule;

static unsigned long long ia32_sysenter_func = 0;
static unsigned long long ia32_syscall_func = 0;
static unsigned long long syscall_func = 0;
static unsigned long tbl_checksum = 0;
static unsigned int scm_gdt_checksum = 0;
static unsigned int scm_idt_checksum = 0;
static unsigned long checksum = 0;

extern const unsigned long sys_call_table[SYS_CALL_TABLE_SIZE];
extern void print_modules(void);

extern void system_call(void);
extern void ia32_syscall(void);
extern void ia32_cstar_target(void);
extern void ia32_sysenter_target(void);

void init_shadow_table(void);
static int scm_proc_open(struct inode *, struct file *);
static int scm_proc_show_events(struct seq_file *, void *);

static const struct file_operations proc_scm_fops = {
    .open = scm_proc_open,
    .read = seq_read,
    .release = single_release,
};

/*
 *  change event log
 */
struct change_event_log {
  struct list_head entry;

  /* addr to the funtions */
  unsigned long o_addr;
  unsigned long c_addr;

  /* syscall number */
  int syscall_nr;

  /*msr change log type*/
  u32 msr_reg;

  /* resposible module */
  char module_name[MODULE_NAME_LEN];
};

static void scm_init_entry_mode(void) {

  if (boot_cpu_has(X86_FEATURE_SYSCALL32)) {
    ia32_syscall_func = native_read_msr(MSR_CSTAR);
    if (ia32_syscall_func) {
      if (ia32_syscall_func != (unsigned long long)ia32_cstar_target)
        printk(KERN_WARNING "syscmon: current IA32e SYSCALL entry differs from "
                            "proper entry point: %llx - %llx\n",
               ia32_syscall_func, (unsigned long long)ia32_cstar_target);
    }

    ia32_sysenter_func = native_read_msr(MSR_IA32_SYSENTER_EIP);
    if (ia32_sysenter_func) {
      if (ia32_sysenter_func != (unsigned long long)ia32_sysenter_target)
        printk(KERN_WARNING
               "syscmon: current IA32e SYSENTER entry differs from "
               "proper entry point: %llx - %llx\n",
               ia32_sysenter_func, (unsigned long long)ia32_sysenter_target);
    }
  }

  if (boot_cpu_has(X86_FEATURE_SEP)) {
    syscall_func = native_read_msr(MSR_LSTAR);
    if (syscall_func) {
      if (syscall_func != (unsigned long long)system_call)
        printk(KERN_WARNING "syscmon: current SYSCALL entry differs from "
                            "proper entry point: %llx - %llx\n",
               syscall_func, (unsigned long long)system_call);
    }
  }

  printk("syscmon: SYSCALL IA32e mode: %s\n"
         "syscmon: SYSENTER IA32e mode: %s\n"
         "syscmon: Fast System Calls in 64-Bit mode: %s\n",
         ia32_syscall_func ? "enabled" : "disabled",
         ia32_sysenter_func ? "enabled" : "disabled",
         syscall_func ? "enabled" : "disabled");
}

/*
 * scm_checksum()
 * Calculate checksum and return this.
 */
static unsigned long scm_checksum(void *addr, unsigned int length) {
  unsigned long csum = 0;
  unsigned long *table = (unsigned long *)addr;

  if (!length || !addr)
    return 0;

  while (length--)
    csum ^= *table++;

  return csum;
}

/*
 * scm_table_change_add()
 * Add a new entry to the changes list.
 */
static int scm_log_add(struct module *mod, unsigned long o_addr,
                       unsigned long c_addr, int syscall_nr, u32 msr_reg) {
  struct change_event_log *log;

  log = kzalloc(sizeof(*log), GFP_KERNEL);
  if (log == NULL)
    return 0;

  INIT_LIST_HEAD(&log->entry);

  if (mod)
    strncpy(log->module_name, mod->name, strlen(mod->name));

  log->o_addr = o_addr;
  log->c_addr = c_addr;
  log->syscall_nr = syscall_nr;
  log->msr_reg = msr_reg;

  spin_lock(&log_list_lock);
  list_add(&log->entry, &event_log_list);
  spin_unlock(&log_list_lock);

  return 1;
}

/*
 * scm_find_log_item()
 * Search entrys in the changes list.
 */
struct change_event_log *scm_find_log_item(unsigned long c_addr, int syscall_nr,
                                           u32 msr) {
  struct change_event_log *log, *ret = NULL;

  spin_lock(&log_list_lock);

  list_for_each_entry(log, &event_log_list, entry) {
    if (log->c_addr == c_addr && log->syscall_nr == syscall_nr &&
        log->msr_reg == msr)
      ret = log;
    else
      continue;
  }
  spin_unlock(&log_list_lock);
  return ret;
}

/*
 * scm_del_event()
 * Clean up old entrys.
 */
void scm_del_event(struct change_event_log *log_entry) {

  list_del(&log_entry->entry);
  kfree(log_entry);
}

static inline void scm_read_idt_entry(gate_desc *gate, unsigned int vector,
                                      unsigned long *idt, unsigned short size) {
  if ((size) && (vector < size))
    memcpy(gate, (unsigned long *)idt[vector], sizeof(*gate));
}

/*
 * get_idt_entry()
 * Get IDT table entry.
 */
static unsigned long get_idt_entry(unsigned int vector) {
  struct desc_ptr dt;
  gate_desc idt_entry;
  unsigned long gate_base;

  native_store_idt(&dt);

  scm_read_idt_entry(&idt_entry, vector, (unsigned long *)dt.address, dt.size);

  gate_base = get_desc_base((struct desc_struct *)&idt_entry);

  return gate_base;
}

/*
 * scm_init_dt_checksums()
 * Stores the initial checksum of the GDT ans IDT.
 */
static void scm_init_dt_checksums(void) {
  struct desc_ptr dt;

  native_store_idt(&dt);

  scm_idt_checksum = scm_checksum((void *)dt.address, (dt.size * sizeof(long)));

  native_store_gdt(&dt);

  scm_gdt_checksum = scm_checksum((void *)dt.address, (dt.size * sizeof(long)));
}

/*
 * scm_get_module()
 * Try to find the module where the address is located.
 */
static struct module *scm_get_module(unsigned long addr) {
  struct module *mod;

  preempt_disable();
  mod = __module_text_address(addr);
  preempt_enable();

  return mod;
}

static int scm_proc_open(struct inode *inode, struct file *file) {
  return single_open(file, scm_proc_show_events, NULL);
}

/*
 * scm_proc_show_events()
 * proc filesystem interface
 */
static int scm_proc_show_events(struct seq_file *s, void *v) {
  struct change_event_log *log;

  seq_printf(s, "%-30s %-30s %-30s %-30s %s\n", "changed syscall number",
             "MSR register", "old address", "new address", "module name");

  spin_lock(&log_list_lock);

  list_for_each_entry(log, &event_log_list, entry) {
    if (log->msr_reg)
      seq_printf(s, "%-30s %-30x %-30lx %-30lx %s\n", "--", log->msr_reg,
                 log->o_addr, log->c_addr,
                 log->module_name ? log->module_name : "kernel");
    else
      seq_printf(s, "%-30i %-30s %-30lx %-30lx %s\n", log->syscall_nr, "--",
                 log->o_addr, log->c_addr,
                 log->module_name ? log->module_name : "kernel");
  }

  spin_unlock(&log_list_lock);

  seq_printf(s, "\n\n");
  seq_printf(s,
             "init sys_call_table checksum: %lx \n"
             "last sys_call_table checksum: %lx \n",
             tbl_checksum, checksum);

  return 0;
}

/*
 * scm_test_func()
 * Worker thread which checks the table periodical.
 */
static int scm_worker_thread(void *unused) {
  unsigned long long entry_addr = 0;
  struct change_event_log *log, *tmp;
  int cpu;
  int i;

#ifdef DEBUG
  printk("sysc_mon: thread was started\n");
#endif

  for (;;) {

    checksum = scm_checksum((void *)sys_call_table, SYS_CALL_TABLE_SIZE);

    if (checksum == tbl_checksum) {
      if (!list_empty(&event_log_list)) {

        spin_lock(&log_list_lock);
        list_for_each_entry_safe(log, tmp, &event_log_list, entry) {
          if (log->syscall_nr > -1 &&
              log->o_addr == sys_call_table[log->syscall_nr]) {
            scm_del_event(log);
          } else
            continue;
        }
        spin_unlock(&log_list_lock);
      }
      goto next;
    }

    // compare each table entry since we are not integer anymore
    for (i = 0; i < NR_syscalls; i++) {

      if ((unsigned long *)sys_call_table[i] ==
          (unsigned long *)shadow_sys_call_tbl[i])
        continue;

      if (scm_find_log_item(sys_call_table[i], i, 0))
        continue;

      kmodule = scm_get_module((unsigned long)sys_call_table[i]);

      scm_log_add(kmodule, (unsigned long)shadow_sys_call_tbl[i],
                  (unsigned long)sys_call_table[i], i, 0);

      if (!kmodule) {

        printk(KERN_WARNING
               "sysc_mon: Attantion entry in the sys call table was changed: \n"
               "o_addr sys call entry: %lx \n"
               "new sys call entry: %lx \n",
               (unsigned long)shadow_sys_call_tbl[i],
               (unsigned long)sys_call_table[i]);

      } else {

        printk(KERN_WARNING
               "sysc_mon: Attantion entry in the sys call table was changed: \n"
               "o_addr sys call entry: %lx \n"
               "new sys call entry: %lx \n"
               "is now located in module: %s\n",
               (unsigned long)shadow_sys_call_tbl[i],
               (unsigned long)sys_call_table[i], kmodule->name);
      }
    }

  next:

#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)

    if (!ia32_sysenter_func)
      goto skip_ia32;

    for_each_present_cpu(cpu) {

      entry_addr = native_read_msr(MSR_IA32_SYSENTER_EIP);
      if (entry_addr != ia32_sysenter_func) {

        if (scm_find_log_item(entry_addr, -1, MSR_IA32_SYSENTER_EIP))
          continue;

        kmodule = scm_get_module(entry_addr);

        scm_log_add(kmodule, (unsigned long)ia32_sysenter_func,
                    (unsigned long)entry_addr, -1, MSR_IA32_SYSENTER_EIP);

        if (!kmodule) {

          printk(KERN_WARNING
                 "sysc_mon: Attantion MSR_IA32_SYSENTER_EIP was changed: \n"
                 "o_addr ia32_sysenter_target: %llx \n"
                 "new ia32_sysenter_target: %llx \n",
                 ia32_sysenter_func, entry_addr);

        } else {

          printk(KERN_WARNING
                 "sysc_mon: Attantion MSR_IA32_SYSENTER_EIP was changed: \n"
                 "o_addr ia32_sysenter_target: %llx \n"
                 "new function ia32_sysenter_target: %llx \n"
                 "is now located in module: %s\n",
                 ia32_sysenter_func, entry_addr, kmodule->name);
        }
      }
    }
  skip_ia32:
#endif

#ifdef CONFIG_X86_64

    /*
     * check consistency of the SYSCALL instruction setup in 64-bit flat code
     * segment mode
     */

    if (!syscall_func)
      goto skip_x64;

    for_each_present_cpu(cpu) {

      entry_addr = native_read_msr(MSR_LSTAR);
      if (entry_addr != syscall_func) {

        if (scm_find_log_item(entry_addr, -1, MSR_LSTAR))
          continue;

        kmodule = scm_get_module((unsigned long)entry_addr);

        scm_log_add(kmodule, (unsigned long)ia32_sysenter_func,
                    (unsigned long)entry_addr, -1, MSR_LSTAR);

        if (!kmodule) {

          printk(KERN_WARNING "sysc_mon: Attantion MSR_LSTAR was changed: \n"
                              "o_addr long SYSCALL target: %llx \n"
                              "new long SYSCALL target: %llx \n",
                 syscall_func, entry_addr);

        } else {

          printk(KERN_WARNING "sysc_mon: Attantion MSR_LSTAR was changed: \n"
                              "o_addr long SYSCALL target: %llx \n"
                              "new function long SYSCALL target: %llx \n"
                              "is now located in module: %s\n",
                 syscall_func, entry_addr, kmodule->name);
        }
      }
    }
  skip_x64:
#endif

    if (!ia32_syscall_func)
      continue;

    for_each_present_cpu(cpu) {

      entry_addr = native_read_msr(MSR_CSTAR);
      if (entry_addr != ia32_syscall_func) {

        if (scm_find_log_item(entry_addr, -1, MSR_CSTAR))
          continue;

        kmodule = scm_get_module((unsigned long)entry_addr);

        scm_log_add(kmodule, (unsigned long)ia32_syscall_func,
                    (unsigned long)entry_addr, -1, MSR_CSTAR);

        if (!kmodule) {

          printk(KERN_WARNING
                 "sysc_mon: Attantion IA32e SYSCALL was changed: \n"
                 "original SYSCALL target: %llx \n"
                 "new SYSCALL target: %llx \n",
                 ia32_syscall_func, entry_addr);

        } else {

          printk(KERN_WARNING
                 "sysc_mon: Attantion IA32e SYSCALL was changed: \n"
                 "original SYSCALL target: %llx \n"
                 "new SYSCALL target: %llx \n"
                 "is now located in module: %s\n",
                 ia32_syscall_func, entry_addr, kmodule->name);
        }
      }
    }

    set_current_state(TASK_INTERRUPTIBLE);

    schedule_timeout(msecs_to_jiffies(SCM_SLEEP));

    if (kthread_should_stop())
      break;
  }

#ifdef DEBUG
  printk("sysc_mon: main thread was killed\n");
#endif

  return 0;
}

void init_shadow_table(void) {

  memcpy(shadow_sys_call_tbl, sys_call_table, SYS_CALL_TABLE_SIZE);

  tbl_checksum = scm_checksum((void *)sys_call_table, SYS_CALL_TABLE_SIZE);
}

static int __init _init_sysc_mon(void) {
  int error = 0;

  printk(KERN_INFO "syscmon: syscall table monitor\n");

  init_shadow_table();

  scm_init_entry_mode();

  INIT_LIST_HEAD(&event_log_list);

  scm_proc_file =
      proc_create_data(SCM_PROC_BASE_NAME, S_IRUGO, NULL, &proc_scm_fops, NULL);
  if (!scm_proc_file) {
    printk(KERN_ERR "syscmon: unable to create %s proc file system entry\n",
           SCM_PROC_BASE_NAME);
  }

  scm_task = kthread_create(scm_worker_thread, NULL, "scm");
  if (IS_ERR(scm_task)) {
    error = PTR_ERR(scm_task);
    printk(KERN_ERR
           "scm_: disabled - Unable to start kernel thread. error=%u\n",
           error);
    return 0;
  }

  wake_up_process(scm_task);
  return 0;
}

#ifdef CONFIG_X86_64
late_initcall(_init_sysc_mon);
#else
subsys_initcall(_init_sysc_mon);
#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("syscall table monitor");
MODULE_AUTHOR("Olaf Schmerse <olase23@gmail.com>");
