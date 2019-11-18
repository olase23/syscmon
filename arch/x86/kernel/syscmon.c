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
#include <linux/spinlock.h>
#include <linux/sys.h>
#include <linux/syscalls.h>

#define DEBUG 1
#define SCM_SLEEP (5 * HZ)
#define SYS_CALL_TABLE_SIZE NR_syscalls * sizeof(long)
#define SCM_PROC_BASE_NAME "syscall_monitor"

static DEFINE_SPINLOCK(scm_spinlock);

static unsigned long *shadow_sys_call_tbl[SYS_CALL_TABLE_SIZE];
static struct mutex scm_mtx;
static struct task_struct *scm_task;
static struct module *kmodule;
static struct list_head change_event_list;
static struct proc_dir_entry *scm_proc_file;

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

static int scm_proc_open(struct inode *, struct file *);
static int scm_proc_show_events(struct seq_file *, void *);

static const struct file_operations proc_scm_fops = {
    .open = scm_proc_open,
    .read = seq_read,
    .release = single_release,
};

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

struct table_change_event {
  /* resposible module */
  struct module *mod;

  /* ptrs to the funtions */
  unsigned long origin;
  unsigned long new_ptr;

  /* syscall number */
  u16 syscall_nr;

  struct list_head entry;
};

// static LIST_HEAD(change_event_list);

/*
 * scm_table_change_add()
 * Add a new entry to the changes list.
 */
int scm_table_change_add(struct module *mod, unsigned long origin,
                         unsigned long new_ptr, u16 syscall_nr) {
  struct table_change_event *event;

  event = kzalloc(sizeof(event), GFP_KERNEL);
  if (event == NULL)
    return 0;

  event->mod = mod;
  event->origin = origin;
  event->new_ptr = new_ptr;
  event->syscall_nr = syscall_nr;

  list_add_tail(&event->entry, &change_event_list);

  return 1;
}

/*
 * scm_find_list_item()
 * Search entrys in the changes list.
 */
int scm_find_list_item(unsigned long new_ptr, u16 syscall_nr) {
  struct table_change_event *event;

  // find a particular entry
  list_for_each_entry(event, &change_event_list, entry) {
    if (event->new_ptr != new_ptr || event->syscall_nr != syscall_nr)
      continue;
    else
      return 1;
  }

  return 0;
}

/*
 * scm_del_event()
 * Clean up old entrys.
 */
int scm_del_event(unsigned long addr, u16 syscall_nr) {
  struct table_change_event *event;
  struct list_head *list, *safe;

  list_for_each_safe(list, safe, &change_event_list) {
    event = list_entry(list, struct table_change_event, entry);
    if (event->syscall_nr == syscall_nr && event->new_ptr != addr) {
      list_del(&event->entry);
      kfree(event);
      return 1;
    }
  }
  return 0;
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

static int scm_proc_show_events(struct seq_file *s, void *v) {
  struct table_change_event *event;
  unsigned long flags;

  seq_printf(s, "%-30s %-30s %-30s %s\n", "intercepted syscall number",
             "origin syscall address", "new address", "module name");

  spin_lock_irqsave(&scm_spinlock, flags);

  list_for_each_entry(event, &change_event_list, entry) {
    seq_printf(s, "%-30i %-30lx %-30lx %s\n", event->syscall_nr, event->origin,
               event->new_ptr, event->mod ? event->mod->name : "kernel");
  }

  spin_unlock_irqrestore(&scm_spinlock, flags);

  return 0;
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

#if defined(CONFIG_X86_32) || defined(CONFIG_IA32_EMULATION)
  ia32_sysenter_func = native_read_msr(MSR_IA32_SYSENTER_EIP);
#endif

#ifdef CONFIG_X86_64
  syscall_func = native_read_msr(MSR_LSTAR);
#endif

  for (;;) {

    checksum = scm_checksum((void *)sys_call_table, SYS_CALL_TABLE_SIZE);

    if (checksum == tbl_checksum) {

      if (!list_empty(&change_event_list)) {

        for (i = 0; i < NR_syscalls; i++)
          scm_del_event(sys_call_table[i], i);
      }

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

  mutex_init(&scm_mtx);

  INIT_LIST_HEAD(&change_event_list);

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
