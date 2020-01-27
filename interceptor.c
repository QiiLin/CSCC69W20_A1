#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <asm/current.h>
#include <asm/ptrace.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/unistd.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/syscalls.h>
#include "interceptor.h"


MODULE_DESCRIPTION("My kernel module");
MODULE_AUTHOR("Me");
MODULE_LICENSE("GPL");

//----- System Call Table Stuff ------------------------------------
/* Symbol that allows access to the kernel system call table */
extern void* sys_call_table[];

/* The sys_call_table is read-only => must make it RW before replacing a syscall */
void set_addr_rw(unsigned long addr) {

	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}

/* Restores the sys_call_table as read-only */
void set_addr_ro(unsigned long addr) {

	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	pte->pte = pte->pte &~_PAGE_RW;

}
//-------------------------------------------------------------


//----- Data structures and bookkeeping -----------------------
/**
 * This block contains the data structures needed for keeping track of
 * intercepted system calls (including their original calls), pid monitoring
 * synchronization on shared data, etc.
 * It's highly unlikely that you will need any globals other than these.
 */

/* List structure - each intercepted syscall may have a list of monitored pids */
struct pid_list {
	pid_t pid;
	struct list_head list;
};


/* Store info about intercepted/replaced system calls */
typedef struct {

	/* Original system call */
	asmlinkage long (*f)(struct pt_regs);

	/* Status: 1=intercepted, 0=not intercepted */
	int intercepted;

	/* Are any PIDs being monitored for this syscall? */
	int monitored;
	/* List of monitored PIDs */
	int listcount;
	struct list_head my_list;
}mytable;

/* An entry for each system call */
mytable table[NR_syscalls+1];

/* Access to the table and pid lists must be synchronized */
spinlock_t pidlist_lock = SPIN_LOCK_UNLOCKED;
spinlock_t calltable_lock = SPIN_LOCK_UNLOCKED;
//-------------------------------------------------------------


//----------LIST OPERATIONS------------------------------------
/**
 * These operations are meant for manipulating the list of pids 
 * Nothing to do here, but please make sure to read over these functions 
 * to understand their purpose, as you will need to use them!
 */

/**
 * Add a pid to a syscall's list of monitored pids. 
 * Returns -ENOMEM if the operation is unsuccessful.
 */
static int add_pid_sysc(pid_t pid, int sysc)
{
	struct pid_list *ple=(struct pid_list*)kmalloc(sizeof(struct pid_list), GFP_KERNEL);

	if (!ple)
		return -ENOMEM;

	INIT_LIST_HEAD(&ple->list);
	ple->pid=pid;

	list_add(&ple->list, &(table[sysc].my_list));
	table[sysc].listcount++;

	return 0;
}

/**
 * Remove a pid from a system call's list of monitored pids.
 * Returns -EINVAL if no such pid was found in the list.
 */
static int del_pid_sysc(pid_t pid, int sysc)
{
	struct list_head *i;
	struct pid_list *ple;

	list_for_each(i, &(table[sysc].my_list)) {

		ple=list_entry(i, struct pid_list, list);
		if(ple->pid == pid) {

			list_del(i);
			kfree(ple);

			table[sysc].listcount--;
			/* If there are no more pids in sysc's list of pids, then
			 * stop the monitoring only if it's not for all pids (monitored=2) */
			if(table[sysc].listcount == 0 && table[sysc].monitored == 1) {
				table[sysc].monitored = 0;
			}

			return 0;
		}
	}

	return -EINVAL;
}

/**
 * Remove a pid from all the lists of monitored pids (for all intercepted syscalls).
 * Returns -1 if this process is not being monitored in any list.
 */
static int del_pid(pid_t pid)
{
	struct list_head *i, *n;
	struct pid_list *ple;
	int ispid = 0, s = 0;

	for(s = 1; s < NR_syscalls; s++) {

		list_for_each_safe(i, n, &(table[s].my_list)) {

			ple=list_entry(i, struct pid_list, list);
			if(ple->pid == pid) {

				list_del(i);
				ispid = 1;
				kfree(ple);

				table[s].listcount--;
				/* If there are no more pids in sysc's list of pids, then
				 * stop the monitoring only if it's not for all pids (monitored=2) */
				if(table[s].listcount == 0 && table[s].monitored == 1) {
					table[s].monitored = 0;
				}
			}
		}
	}

	if (ispid) return 0;
	return -1;
}

/**
 * Clear the list of monitored pids for a specific syscall.
 */
static void destroy_list(int sysc) {

	struct list_head *i, *n;
	struct pid_list *ple;

	list_for_each_safe(i, n, &(table[sysc].my_list)) {

		ple=list_entry(i, struct pid_list, list);
		list_del(i);
		kfree(ple);
	}

	table[sysc].listcount = 0;
	table[sysc].monitored = 0;
}

/**
 * Check if two pids have the same owner - useful for checking if a pid 
 * requested to be monitored is owned by the requesting process.
 * Remember that when requesting to start monitoring for a pid, only the 
 * owner of that pid is allowed to request that.
 */
static int check_pid_from_list(pid_t pid1, pid_t pid2) {

	struct task_struct *p1 = pid_task(find_vpid(pid1), PIDTYPE_PID);
	struct task_struct *p2 = pid_task(find_vpid(pid2), PIDTYPE_PID);
	if(p1->real_cred->uid != p2->real_cred->uid)
		return -EPERM;
	return 0;
}

/**
 * Check if a pid is already being monitored for a specific syscall.
 * Returns 1 if it already is, or 0 if pid is not in sysc's list.
 */
static int check_pid_monitored(int sysc, pid_t pid) {

	struct list_head *i;
	struct pid_list *ple;

	list_for_each(i, &(table[sysc].my_list)) {

		ple=list_entry(i, struct pid_list, list);
		if(ple->pid == pid)
			return 1;

	}
	return 0;
}
//----------------------------------------------------------------

//----- Intercepting exit_group ----------------------------------
/**
 * Since a process can exit without its owner specifically requesting
 * to stop monitoring it, we must intercept the exit_group system call
 * so that we can remove the exiting process's pid from *all* syscall lists.
 */

/** 
 * Stores original exit_group function - after all, we must restore it 
 * when our kernel module exits.
 */
void (*orig_exit_group)(int);

/**
 * Our custom exit_group system call.
 *
 * TODO: When a process exits, make sure to remove that pid from all lists.
 * The exiting process's PID can be retrieved using the current variable (current->pid).
 * Don't forget to call the original exit_group.
 */
void my_exit_group(int status) {
    /* get the lock and delete pid and then release the lock */
    spin_lock(&pidlist_lock);
    del_pid(current->pid);
    spin_unlock(&pidlist_lock);

    orig_exit_group(status);
}
//----------------------------------------------------------------



/** 
 * This is the generic interceptor function.
 * It should just log a message and call the original syscall.
 * 
 * TODO: Implement this function. 
 * - Check first to see if the syscall is being monitored for the current->pid. 
 * - Recall the convention for the "monitored" flag in the mytable struct: 
 *     monitored=0 => not monitored
 *     monitored=1 => some pids are monitored, check the corresponding my_list
 *     monitored=2 => all pids are monitored for this syscall
 * - Use the log_message macro, to log the system call parameters!
 *     Remember that the parameters are passed in the pt_regs registers.
 *     The syscall parameters are found (in order) in the 
 *     ax, bx, cx, dx, si, di, and bp registers (see the pt_regs struct).
 * - Don't forget to call the original system call, so we allow processes to proceed as normal.
 */
asmlinkage long interceptor(struct pt_regs reg) {

    extern int check_pid_monitored_with_blacklist(int syscall, int pid);

    /* if pid is monitored, then log the message */
    if (check_pid_monitored_with_blacklist(reg.ax, current->pid)) {
        log_message(current->pid, reg.ax, reg.bx, reg.cx, reg.dx, reg.si, reg.di, reg.bp);
    }


    return table[reg.ax].f(reg);
}

/**
 * The function is used to check if the pid has been monitored.
 * Using blacklist strategy mentioned in the handout.
 * Recall:
 *      monitored=0 => nothing has been monitored
 *      monitored=1 => my_list has all pids that has been monitored
 *      monitored=2 => my_list has all pids that hasn't been monitored;
 *                     therefore, it monitors all other pids not in my_list
 *
 * @param syscall is the system call to check
 * @param pid is the pid to check
 * @return 1 if pid is been monitored by syscall,
 *         0 otherwise
 */
int check_pid_monitored_with_blacklist(int syscall, int pid) {
    int status;
    switch (table[syscall].monitored) {
        case 0:
            status = 0;
            break;
        case 1:
            status = check_pid_monitored(syscall, pid);
            break;
        default:
            status = !check_pid_monitored(syscall, pid);
    }
    return status;
}

/**
 * My system call - this function is called whenever a user issues a MY_CUSTOM_SYSCALL system call.
 * When that happens, the parameters for this system call indicate one of 4 actions/commands:
 *      - REQUEST_SYSCALL_INTERCEPT to intercept the 'syscall' argument
 *      - REQUEST_SYSCALL_RELEASE to de-intercept the 'syscall' argument
 *      - REQUEST_START_MONITORING to start monitoring for 'pid' whenever it issues 'syscall'
 *      - REQUEST_STOP_MONITORING to stop monitoring for 'pid'
 *      For the last two, if pid=0, that translates to "all pids".
 *
 * TODO: Implement this function, to handle all 4 commands correctly.
 *
 * - For each of the commands, check that the arguments are valid (-EINVAL):
 *   a) the syscall must be valid (not negative, not > NR_syscalls, and not MY_CUSTOM_SYSCALL itself)
 *   b) the pid must be valid for the last two commands. It cannot be a negative integer,
 *      and it must be an existing pid (except for the case when it's 0, indicating that we want
 *      to start/stop monitoring for "all pids").
 *      If a pid belongs to a valid process, then the following expression is non-NULL:
 *           pid_task(find_vpid(pid), PIDTYPE_PID)
 * - Check that the caller has the right permissions (-EPERM)
 *      For the first two commands, we must be root (see the current_uid() macro).
 *      For the last two commands, the following logic applies:
 *        - is the calling process root? if so, all is good, no doubts about permissions.
 *        - if not, then check if the 'pid' requested is owned by the calling process
 *        - also, if 'pid' is 0 and the calling process is not root, then access is denied
 *          (monitoring all pids is allowed only for root, obviously).
 *      To determine if two pids have the same owner, use the helper function provided above in this file.
 * - Check for correct context of commands (-EINVAL):
 *     a) Cannot de-intercept a system call that has not been intercepted yet.
 *     b) Cannot stop monitoring for a pid that is not being monitored, or if the
 *        system call has not been intercepted yet.
 * - Check for -EBUSY conditions:
 *     a) If intercepting a system call that is already intercepted.
 *     b) If monitoring a pid that is already being monitored.
 * - If a pid cannot be added to a monitored list, due to no memory being available,
 *   an -ENOMEM error code should be returned.
 *
 * - Make sure to keep track of all the metadata on what is being intercepted and monitored.
 *   Use the helper functions provided above for dealing with list operations.
 *
 * - Whenever altering the sys_call_table, make sure to use the set_addr_rw/set_addr_ro functions
 *   to make the system call table writable, then set it back to read-only.
 *   For example: set_addr_rw((unsigned long)sys_call_table);
 *   Also, make sure to save the original system call (you'll need it for 'interceptor' to work correctly).
 *
 * - Make sure to use synchronization to ensure consistency of shared data structures.
 *   Use the calltable_spinlock and pidlist_spinlock to ensure mutual exclusion for accesses
 *   to the system call table and the lists of monitored pids. Be careful to unlock any spinlocks
 *   you might be holding, before you exit the function (including error cases!).
 */
asmlinkage long my_syscall(int cmd, int syscall, int pid) {

    int status = 0;
    extern int is_cmd_has_no_permission(int cmd, int pid);
    extern int check_pid_monitored_with_blacklist(int syscall, int pid);

    /* check if cmd is not these four options */
    if (cmd != REQUEST_SYSCALL_INTERCEPT &&
        cmd != REQUEST_SYSCALL_RELEASE &&
        cmd != REQUEST_START_MONITORING &&
        cmd != REQUEST_STOP_MONITORING) {
        return -EINVAL;
    }

    /* check if syscall is valid (-EINVAL) */
    if (syscall < 0 || syscall > NR_syscalls ||
        syscall == MY_CUSTOM_SYSCALL) {
        return -EINVAL;
    }

    /* check if pid is valid (-EINVAL) */
    if (pid < 0 ||
        (pid != 0 && pid_task(find_vpid(pid), PIDTYPE_PID) == NULL)) {
        return -EINVAL;
    }

    /* check for right permission (-EPERM) */
    if (is_cmd_has_no_permission(cmd, pid)) {
        return -EPERM;
    }

    /* execute cmd based on its type */
    switch (cmd) {
        case REQUEST_SYSCALL_INTERCEPT:
            /* check if syscall has been intercepted (-EBUSY) */
            if (table[syscall].intercepted) {
                return -EBUSY;
            }

            /*
             * 1. record function to mytable.f
             * 2. make sys_call_table pointing to our interceptor
             * 3. set intercepted signal to 1
             */
            spin_lock(&calltable_lock);

            table[syscall].f = sys_call_table[syscall];
            set_addr_rw((unsigned long) sys_call_table);
            sys_call_table[syscall] = interceptor;
            set_addr_ro((unsigned long) sys_call_table);
            table[syscall].intercepted = 1;

            spin_unlock(&calltable_lock);

            break;

        case REQUEST_SYSCALL_RELEASE:
            /* check if syscall is not been intercepted (-EINVAL) */
            if (!table[syscall].intercepted) {
                return -EINVAL;
            }

            /*
             * 1. set sys_call_table back to its original function
             * 2. set intercepted signal to 0
             */
            spin_lock(&calltable_lock);

            set_addr_rw((unsigned long) sys_call_table);
            sys_call_table[syscall] = table[syscall].f;
            set_addr_ro((unsigned long) sys_call_table);
            table[syscall].intercepted = 0;

            spin_unlock(&calltable_lock);

            break;

        case REQUEST_START_MONITORING:
            /* check if pid has been monitored (-EBUSY) */
            if (check_pid_monitored_with_blacklist(syscall, pid)) {
                return -EBUSY;
            }

            /**
             * can't start monitoring on a syscall not intercepted
             */ 
            if (table[syscall].intercepted == 0){
                return -EINVAL;
            }

            /*
             * if one syscall is already monitored for all pids and request monitoring
             * for all pids again, return an error
             */
            if (pid==0 && table[syscall].monitored == 2 && table[syscall].listcount == 0){
                return -EBUSY;
            }

            /*
             * this is the case that pid is 0 (for all pids)
             * we need to convert whitelist to blacklist:
             *      1. clean all the pids in my_list
             *      2. and then mark monitored signal to 2
             */
            spin_lock(&pidlist_lock);
            if (pid == 0) {
                destroy_list(syscall);
                table[syscall].monitored = 2;
            }

                /* this is the case that pid is not 0 (not for all pids) */
            else if (table[syscall].monitored < 2) {
                /*
                 * whitelist case:
                 *      my_list stores all pids that are monitored
                 */
                status = add_pid_sysc(pid, syscall);
                table[syscall].monitored |= 1;
            } else {
                /*
                 * blacklist case:
                 *      my_list stores all pids that are non-monitored
                 */
                status = del_pid_sysc(pid, syscall);
            }
            spin_unlock(&pidlist_lock);

            break;

        default: /* must be the case REQUEST_STOP_MONITORING */
            /* check if pid is not been monitored (-EINVAL) */
            if (!check_pid_monitored_with_blacklist(syscall, pid)) {
                return -EINVAL;
            }

			/*
			 * check whether the syscall is intercepted
			 */
			if (table[syscall].intercepted == 0) {
				return -EINVAL;
			}

            /*
            * if not monitored and request to stop monitoring for all
            * return an error
            */
            if (table[syscall].monitored == 0 && pid == 0){
                return -EINVAL;
            }

            /*
             * this is the case that pid is 0 (for all pids)
             * we need to convert blacklist to whitelist:
             *      1. clean all the pids in my_list
             *      2. and then mark monitored signal to 0
             */
            spin_lock(&pidlist_lock);
            if (pid == 0) {
                destroy_list(syscall);
                table[syscall].monitored = 0;
            }

                /* this is the case that pid is not 0 (not for all pids) */
            else if (table[syscall].monitored < 2) {
                /*
                 * whitelist case:
                 *      my_list stores all pids that are monitored
                 */
                status = del_pid_sysc(pid, syscall);
            } else {
                /*
                 * blacklist case:
                 *      my_list stores all pids that are non-monitored
                 */
                status = add_pid_sysc(pid, syscall);
            }
            spin_unlock(&pidlist_lock);
    }

    return status;
}

/**
 * The function will check if the caller has the wrong permission.
 *
 * @param cmd is the command to check
 * @param pid is the pid to check
 * @return 0, if caller has the right permission
 *         otherwise, caller has no permission
 */
int is_cmd_has_no_permission(int cmd, int pid) {
    if (cmd == REQUEST_SYSCALL_INTERCEPT || cmd == REQUEST_SYSCALL_RELEASE) {
        /*
         * if current_uid is 0, then caller has the permission,
         * if current_uid is not 0, then no permission.
         */
        return current_uid();
    } else {
        if (pid == 0) {
            /* same, since monitoring all pids is allowed only for root */
            return current_uid();
        } else {
            /*
             * check_pid_from_list returns 0 if two pids have the same owen,
             * which means caller has the permission, so we could just return its value.
             */
            return check_pid_from_list(current->pid, pid);
        }
    }
}

/**
 *
 */
long (*orig_custom_syscall)(void);


/**
 * Module initialization.
 *
 * TODO: Make sure to:
 * - Hijack MY_CUSTOM_SYSCALL and save the original in orig_custom_syscall.
 * - Hijack the exit_group system call (__NR_exit_group) and save the original
 *   in orig_exit_group.
 * - Make sure to set the system call table to writable when making changes,
 *   then set it back to read only once done.
 * - Perform any necessary initializations for bookkeeping data structures.
 *   To initialize a list, use
 *        INIT_LIST_HEAD (&some_list);
 *   where some_list is a "struct list_head".
 * - Ensure synchronization as needed.
 */
static int init_function(void) {

    int i;

    /* init spin locks */
    spin_lock_init(&calltable_lock);
    spin_lock_init(&pidlist_lock);

    /* stores two system calls */
    orig_custom_syscall = sys_call_table[MY_CUSTOM_SYSCALL];
    orig_exit_group = sys_call_table[__NR_exit_group];

    /* hijack two system calls */
    spin_lock(&calltable_lock);
    set_addr_rw((unsigned long) sys_call_table);
    sys_call_table[MY_CUSTOM_SYSCALL] = my_syscall;
    sys_call_table[__NR_exit_group] = my_exit_group;
    set_addr_ro((unsigned long) sys_call_table);
    spin_unlock(&calltable_lock);

    /* initialize all syscalls in table */
    spin_lock(&pidlist_lock);
    for (i = 0; i < NR_syscalls + 1; ++i) {
        table[i].monitored = 0;
        table[i].intercepted = 0;
        table[i].listcount = 0;
        table[i].f = sys_call_table[i];
        INIT_LIST_HEAD(&table[i].my_list);
    }
    spin_unlock(&pidlist_lock);

    return 0;
}

/**
 * Module exits.
 *
 * TODO: Make sure to:
 * - Restore MY_CUSTOM_SYSCALL to the original syscall.
 * - Restore __NR_exit_group to its original syscall.
 * - Make sure to set the system call table to writable when making changes,
 *   then set it back to read only once done.
 * - Ensure synchronization, if needed.
 */
static void exit_function(void) {

    int i;

    /* restore all syscalls and destroy my_list of pids */
    spin_lock(&calltable_lock);
    set_addr_rw((unsigned long) sys_call_table);
    spin_lock(&pidlist_lock);

    for (i = 0; i < NR_syscalls + 1; ++i) {
        sys_call_table[i] = table[i].f;
        destroy_list(i);
    }
    spin_unlock(&pidlist_lock);

    /* restore two hijacked functions */
    sys_call_table[MY_CUSTOM_SYSCALL] = orig_custom_syscall;
    sys_call_table[__NR_exit_group] = orig_exit_group;
    set_addr_ro((unsigned long) sys_call_table);
    spin_unlock(&calltable_lock);

}

module_init(init_function);
module_exit(exit_function);