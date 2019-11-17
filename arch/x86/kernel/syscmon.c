#include <linux/module.h>

#include <asm/asm-offsets.h>
#include <asm/cpufeature.h>
#include <asm/desc.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/syscalls.h>
#include <asm/unistd.h>
#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/linkage.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/sys.h>
#include <linux/syscalls.h>

#define DEBUG 1
#define SCM_SLEEP (5 * HZ)
#define SYS_CALL_TABLE_SIZE NR_syscalls * sizeof(long)

static unsigned long *shadow_sys_call_tbl[SYS_CALL_TABLE_SIZE];
// static struct   mutex       scm_mtx;
static struct task_struct *scm_task;
static struct module *kmodule;

static unsigned long tbl_checksum = 0;
static unsigned int scm_gdt_checksum = 0;
static unsigned int scm_idt_checksum = 0;

#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)
static unsigned long long ia32_sysenter_func = 0;
#endif

#ifdef CONFIG_X86_64
static unsigned long long syscall_func = 0;
#endif

void init_shadow_table(void);

extern const unsigned long sys_call_table[SYS_CALL_TABLE_SIZE];

extern void print_modules(void);
asmlinkage int system_call(void);

/*
 * scm_checksum()
 * Calculate checksum and return this.
 */
static unsigned long scm_checksum(void *addr, unsigned int length) {
  unsigned long checksum = 0;
  unsigned long *table = (unsigned long *)addr;

  if (!length || !addr)
    return 0;

  while (length--)
    checksum ^= *table++;

  return checksum;
}

struct sys_call_table_change {
  /* resposible module */
  struct module *mod;

  /* ptrs to the funtions */
  unsigned long origin;
  unsigned long new_ptr;

  /* syscall number */
  u16 syscall_nr;

  struct list_head next;
};

static LIST_HEAD(table_change_list);

/*
 * scm_table_change_add()
 * Add a new entry to the changes list.
 */
int scm_table_change_add(struct module *mod, unsigned long origin,
                         unsigned long new_ptr, u16 syscall_nr) {
  struct sys_call_table_change *item;

  item = kzalloc(sizeof(item), GFP_KERNEL);
  if (item == NULL)
    return 0;

  item->mod = mod;
  item->origin = origin;
  item->new_ptr = new_ptr;
  item->syscall_nr = syscall_nr;

  list_add_tail(&item->next, &table_change_list);

  return 1;
}

/*
 * scm_find_list_item()
 * Search entrys in the changes list.
 */
int scm_find_list_item(unsigned long new_ptr, u16 syscall_nr) {
  struct sys_call_table_change *item;

  // find a particular entry
  list_for_each_entry(item, &table_change_list, next) {
    if (item->new_ptr != new_ptr || item->syscall_nr != syscall_nr)
      continue;
    else
      return 1;
  }

  return 0;
}

/*
 * scm_find_list_item()
 * Clean up old entrys.
 */
int scm_clean_up_list(unsigned long addr, u16 syscall_nr) {
  struct sys_call_table_change *item;

  list_for_each_entry(item, &table_change_list, next) {
    if (item->syscall_nr == syscall_nr && item->new_ptr != addr) {
      printk("Found a list entry for deletion. %lx - %i\n", addr, syscall_nr);

      list_del(&item->next);
      kfree(item);
      return 1;
    }
  }
  return 0;
}

/*
 * scm_free_list()
 *
 */
void scm_free_list(void) {
  struct sys_call_table_change *item;
  struct list_head *list, *safe;

  if (list_empty(&table_change_list))
    return;

  list_for_each_safe(list, safe, &table_change_list) {
    item = list_entry(list, struct sys_call_table_change, next);
    printk("scm_free_list: Debug1\n");

    list_del(&item->next);
    printk("scm_free_list: Debug2\n");

    kfree(item);
    printk("scm_free_list: Debug3\n");
  }
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

/*
 * scm_test_func()
 * Worker thread which checks the table periodical.
 */
static int scm_worker_thread(void *unused) {
  unsigned long long _addr_ = 0;
  unsigned long checksum = 0;
  int i;

#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)
  unsigned long long ia32_addr;
#endif

#ifdef DEBUG
  printk("sysc_mon: thread was started\n");
#endif
  // save the currennt segment discriptors
  // scm_init_dt_checksums();

#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)
  ia32_sysenter_func = native_read_msr(MSR_IA32_SYSENTER_EIP);
#endif

#ifdef CONFIG_X86_64
  syscall_func = native_read_msr(MSR_LSTAR);
#endif

  for (;;) {

    checksum = scm_checksum((void *)sys_call_table, SYS_CALL_TABLE_SIZE);

    if (checksum == tbl_checksum) {

      scm_free_list();
      goto next;
    }

    // compare each table entry since we are not integer anymore
    for (i = 0; i < NR_syscalls; i++) {

      if ((unsigned long *)sys_call_table[i] ==
          (unsigned long *)shadow_sys_call_tbl[i])
        continue;

      if (scm_find_list_item(sys_call_table[i], i))
        continue;

      kmodule = scm_get_module((unsigned long)sys_call_table[i]);

      scm_table_change_add(kmodule, (unsigned long)shadow_sys_call_tbl[i],
                           (unsigned long)sys_call_table[i], i);

      if (!kmodule) {

        printk(KERN_WARNING
               "sysc_mon: Attantion entry in the sys call table was changed: \n"
               "origin sys call entry: %lx \n"
               "new sys call entry: %lx \n",
               (unsigned long)shadow_sys_call_tbl[i],
               (unsigned long)sys_call_table[i]);

      } else {

        printk(KERN_WARNING
               "sysc_mon: Attantion entry in the sys call table was changed: \n"
               "origin sys call entry: %lx \n"
               "new sys call entry: %lx \n"
               "is now located in module: %s\n",
               (unsigned long)shadow_sys_call_tbl[i],
               (unsigned long)sys_call_table[i], kmodule->name);
      }
    }

  next:
#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)

    ia32_addr = native_read_msr(MSR_IA32_SYSENTER_EIP);
    if (ia32_addr != ia32_sysenter_func) {

      if (ia32_addr) {

        kmodule = scm_get_module(ia32_addr);

        if (!kmodule) {

          printk(KERN_WARNING
                 "sysc_mon: Attantion MSR_IA32_SYSENTER_EIP was changed: \n"
                 "origin ia32_sysenter_target: %llx \n"
                 "new ia32_sysenter_target: %llx \n",
                 ia32_sysenter_func, ia32_addr);

        } else {

          printk(KERN_WARNING
                 "sysc_mon: Attantion MSR_IA32_SYSENTER_EIP was changed: \n"
                 "origin ia32_sysenter_target: %llx \n"
                 "new function ia32_sysenter_target: %llx \n"
                 "is now located in module: %s\n",
                 ia32_sysenter_func, ia32_addr, kmodule->name);
        }
      }
    }

#endif

#ifdef CONFIG_X86_64

    /*
     * check consistency of the SYSCALL instruction setup in 64-bit flat code
     * segment mode
     */

    if (syscall_func != 0) {

      _addr_ = native_read_msr(MSR_LSTAR);
      if (_addr_ != syscall_func) {

        if (_addr_) {

          kmodule = scm_get_module((unsigned long)_addr_);

          if (!kmodule) {

            printk(KERN_WARNING "sysc_mon: Attantion MSR_LSTAR was changed: \n"
                                "origin ia32_sysenter_target: %llx \n"
                                "new ia32_sysenter_target: %llx \n",
                   syscall_func, _addr_);

          } else {

            printk(KERN_WARNING "sysc_mon: Attantion MSR_LSTAR was changed: \n"
                                "origin ia32_sysenter_target: %llx \n"
                                "new function ia32_sysenter_target: %llx \n"
                                "is now located in module: %s\n",
                   syscall_func, _addr_, kmodule->name);
          }
        }
      }
    }
#endif

    schedule_timeout(msecs_to_jiffies(SCM_SLEEP));

    set_current_state(TASK_INTERRUPTIBLE);

    if (kthread_should_stop())
      break;
  }

#ifdef DEBUG
  printk("sysc_mon: thread was killed\n");
#endif

  return 0;
}

/*
 * init_shadow_table()
 * Try to find the module and print its name.
 */
void init_shadow_table(void) {

  memcpy(shadow_sys_call_tbl, sys_call_table, SYS_CALL_TABLE_SIZE);

  tbl_checksum = scm_checksum((void *)sys_call_table, SYS_CALL_TABLE_SIZE);
}

static int __init _init_sysc_mon(void) {
  int error = 0;

#ifdef DEBUG
  printk(KERN_DEBUG "sysc_mon: ---> _init_sysc_mon()\n");
#endif

  init_shadow_table();

  scm_task = kthread_create(scm_worker_thread, NULL, "scm");
  if (IS_ERR(scm_task)) {
    error = PTR_ERR(scm_task);
    printk(KERN_ERR
           "scm_: disabled - Unable to start kernel thread. error=%u\n",
           error);
    return 0;
  }

  wake_up_process(scm_task);

#ifdef DEBUG
  printk(KERN_DEBUG "sysc_mon: <--- _init_sysc_mon()\n");
#endif

  return 0;
}

static void __exit _stop_sysc_mon(void) {

#ifdef DEBUG
  printk(KERN_DEBUG "sysc_mon: ---> _stop_sysc_mon()\n");
#endif

  kthread_stop(scm_task);

#ifdef DEBUG
  printk(KERN_DEBUG "sysc_mon: <--- _stop_sysc_mon()\n");
#endif
}

#ifdef CONFIG_X86_64
late_initcall(_init_sysc_mon);
#else
subsys_initcall(_init_sysc_mon);
#endif

MODULE_LICENSE("GPL");
