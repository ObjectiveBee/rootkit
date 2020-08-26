#include <linux/module.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>

#include <linux/unistd.h> // numbers of syscalls //

#include <linux/uaccess.h>
#include <linux/slab.h>

// #include <linux/tty.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexey Safonov");
MODULE_DESCRIPTION("");

int (*real_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
int (*real_getdents)(unsigned int, struct linux_dirent *, unsigned int);

/*
static void printString(char *string)
{
	struct tty_struct *tty;
	tty = get_current_tty();
	if(tty != NULL)
		(tty->driver->ops->write)(tty, string, strlen(string));
	else
		printk("tty equals to zero\n");
}*/

unsigned long *table;

static inline void protect_memory(void)
{
	asm("pushq %rax");
	asm("movq %cr0, %rax");
	asm("xorq $0x0000000000010000, %rax");
	asm("movq %rax, %cr0");
	asm("popq %rax");
}

static inline void unprotect_memory(void)
{
	asm("pushq %rax");
	asm("movq %cr0, %rax");
	asm("andq $0xfffffffffffeffff, %rax");
	asm("movq %rax, %cr0");
	asm("popq %rax");
}

struct linux_derent64 {
	unsigned long long 	d_ino;
	signed long long	d_off;
	unsigned short		d_reclen;
	unsigned char		d_type;
	char			d_name[];
};

/*
struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[];
};
*/

unsigned long *get_syscall_table_bf(void)
{
	unsigned long *syscall_table;

	syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
}

int new_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{
	int ret = real_getdents64(fd, dirp, count);
	
	printk("getdents64 syscall\n");

	return ret;
}

/*
int new_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	int ret = real_getdents(fd, dirp, count);

	return ret;
}
*/

void hooking_syscall(void)
{
	unprotect_memory();

	real_getdents64 = (void *)table[__NR_getdents64];
	// real_getdents = (void *)table[__NR_getdents];
	table[__NR_getdents64] = (unsigned long)new_getdents64;
	// table[__NR_getdents] = (unsigned long)new_getdents;

	protect_memory();
	
	printk("Success hook\n");
}

void unhooking_syscall(void)
{
	unprotect_memory();
	table[__NR_getdents64] = (unsigned long)real_getdents64;
	// table[__NR_getdents] = (unsigned long)real_getdents;
	protect_memory();

	printk("Success unhook\n");
}

static int __init start(void)
{
	table = get_syscall_table_bf();

	printk("Module has been loaded!\n");

	hooking_syscall();

	return 0;
}

static void __exit stop(void)
{
	unhooking_syscall();
	printk("Module has been removed\n");
}

module_init(start);
module_exit(stop);
