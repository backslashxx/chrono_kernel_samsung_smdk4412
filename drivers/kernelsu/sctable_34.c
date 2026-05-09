#ifndef CONFIG_ARM
#error "only meant for ARM"
#endif

#include <asm/cacheflush.h>
#include <asm/pgtable.h>

#define FORCE_VOLATILE(x) *(volatile typeof(x) *)&(x)

#define __ARMEABI_reboot	88
#define __ARMEABI_execve	11
#define __ARMEABI_faccessat	334
#define __ARMEABI_fstatat64	327
#define __ARMEABI_fstat64	197
#define __ARMEABI_read		3

asmlinkage long (*armeabi_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg) __read_mostly = NULL;
asmlinkage long hook_armeabi_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
	return armeabi_reboot(magic1, magic2, cmd, arg);
}

asmlinkage long (*armeabi_execve)(const char __user * filename,
				const char __user *const __user * argv,
				const char __user *const __user * envp) __read_mostly = NULL;
asmlinkage long hook_armeabi_execve(const char __user * filename,
				const char __user *const __user * argv,
				const char __user *const __user * envp)
{
	ksu_handle_execve(&filename, (void ***)&argv, (void ***)&envp);
	return armeabi_execve(filename, argv, envp);
}

asmlinkage long (*armeabi_faccessat)(int dfd, const char __user * filename, int mode) __read_mostly = NULL;
asmlinkage long hook_armeabi_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return armeabi_faccessat(dfd, filename, mode);
}

asmlinkage long (*armeabi_fstatat64)(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag) __read_mostly = NULL;
asmlinkage long hook_armeabi_fstatat64(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return armeabi_fstatat64(dfd, filename, statbuf, flag);
}

asmlinkage long (*armeabi_fstat64)(unsigned long fd, struct stat64 __user * statbuf) __read_mostly = NULL;
asmlinkage long hook_armeabi_fstat64_ret(unsigned long fd, struct stat64 __user * statbuf)
{
	// we handle it like rp
	long ret = armeabi_fstat64(fd, statbuf);
	ksu_handle_fstat64_ret(&fd, &statbuf);
	return ret;
}

asmlinkage long (*armeabi_read)(unsigned int fd, char __user *buf, size_t count) __read_mostly = NULL;
asmlinkage long hook_armeabi_read(unsigned int fd, char __user *buf, size_t count)
{
	ksu_handle_sys_read_fd(fd);
	return armeabi_read(fd, buf, count);
}

// WARNING!!! void * abuse ahead! (type-punning, pointer-hiding!)
// for 4.19+ old_ptr is actually syscall_fn_t *, which is just long * so we can consider this void **
// for 4.19- old_ptr is actually void **
// target_table is void *target_table[];
static void read_and_replace_syscall(void *old_ptr, unsigned long syscall_nr, void *new_ptr, void *target_table)
{
	void **sctable = (void **)target_table;
	void **syscall_slot_addr = &sctable[syscall_nr];

	if (!*syscall_slot_addr)
		return;

	pr_info("%s: hooking syscall #%d at 0x%lx\n", __func__, syscall_nr, (long)syscall_slot_addr);

	/*
	 * basically the trick is
	 * addr, say 0xffff1234, this is READ-ONLY
	 * align it, 0xffff0000
	 * ptrdiff 0xffff1234 - 0xffff0000, 0x00001234
	 * vmap 0xffff0000, say we get 0xcccc0000 , now WRITABLE
	 * write on 0xcccc0000 + 0x00001234
	 *
	 */

	// prep vmap alias
	unsigned long addr = (unsigned long)syscall_slot_addr;
	unsigned long base = addr & PAGE_MASK;
	unsigned long offset = addr & ~PAGE_MASK; // offset_in_page

	// this is impossible for our case because the page alignment
	// but be careful for other cases!
	// BUG_ON(offset + len > PAGE_SIZE);
	if (offset + sizeof(void *) > PAGE_SIZE) {
		pr_info("%s: syscall slot crosses page boundary! aborting.\n", __func__);
		return;
	}

	// virtual mapping of a physical page 
	struct page *page = phys_to_page(__pa(base));
	if (!page)
		return;

	// create a "writabel address" which is mapped to teh same address
	void *writable_addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
	if (!writable_addr)
		return;

	// swap on the alias
	void **target_slot = (void **)((unsigned long)writable_addr + offset);

	preempt_disable();
	local_irq_disable();

	*(void **)old_ptr = *target_slot; 

	*target_slot = new_ptr;
	smp_mb(); // ^^

	local_irq_enable();
	preempt_enable();

	vunmap(writable_addr);

	smp_mb(); 
}

static void test_xd()
{
	unsigned long *sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

	read_and_replace_syscall((void *)&armeabi_execve, __ARMEABI_execve, (void *)hook_armeabi_execve, (void *)sys_call_table);
	read_and_replace_syscall((void *)&armeabi_faccessat, __ARMEABI_faccessat, (void *)hook_armeabi_faccessat, (void *)sys_call_table);
	read_and_replace_syscall((void *)&armeabi_fstatat64, __ARMEABI_fstatat64, (void *)hook_armeabi_fstatat64, (void *)sys_call_table);
}

static __init int ksu_syscall_table_hook_init()
{
	unsigned long *sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

	read_and_replace_syscall((void *)&armeabi_reboot, __ARMEABI_reboot, (void *)hook_armeabi_reboot, (void *)sys_call_table);

//	read_and_replace_syscall((void *)&armeabi_execve, __ARMEABI_execve, (void *)hook_armeabi_execve, (void *)sys_call_table);
//	read_and_replace_syscall((void *)&armeabi_faccessat, __ARMEABI_faccessat, (void *)hook_armeabi_faccessat, (void *)sys_call_table);
//	read_and_replace_syscall((void *)&armeabi_fstatat64, __ARMEABI_fstatat64, (void *)hook_armeabi_fstatat64, (void *)sys_call_table);

//	read_and_replace_syscall((void *)&armeabi_fstat64, __ARMEABI_fstat64, (void *)hook_armeabi_fstat64_ret, (void *)sys_call_table);

	return 0;
}
device_initcall_sync(ksu_syscall_table_hook_init);

// EOF
