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
__attribute__((hot))
asmlinkage long hook_armeabi_execve(const char __user * filename,
				const char __user *const __user * argv,
				const char __user *const __user * envp)
{
	ksu_handle_execve(&filename, (void ***)&argv, (void ***)&envp);
	return armeabi_execve(filename, argv, envp);
}

asmlinkage long (*armeabi_faccessat)(int dfd, const char __user * filename, int mode) __read_mostly = NULL;
__attribute__((hot))
asmlinkage long hook_armeabi_faccessat(int dfd, const char __user * filename, int mode)
{
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
	return armeabi_faccessat(dfd, filename, mode);
}

asmlinkage long (*armeabi_fstatat64)(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag) __read_mostly = NULL;
__attribute__((hot))
asmlinkage long hook_armeabi_fstatat64(int dfd, const char __user * filename, struct stat64 __user * statbuf, int flag)
{
	ksu_handle_stat(&dfd, &filename, &flag);
	return armeabi_fstatat64(dfd, filename, statbuf, flag);
}

asmlinkage long (*armeabi_fstat64)(unsigned long fd, struct stat64 __user * statbuf) __read_mostly = NULL;
__attribute__((cold))
asmlinkage long hook_armeabi_fstat64_ret(unsigned long fd, struct stat64 __user * statbuf)
{
	// we handle it like rp
	long ret = armeabi_fstat64(fd, statbuf);
	ksu_handle_fstat64_ret(&fd, &statbuf);
	return ret;
}

asmlinkage long (*armeabi_read)(unsigned int fd, char __user *buf, size_t count) __read_mostly = NULL;
__attribute__((cold))
asmlinkage long hook_armeabi_read(unsigned int fd, char __user *buf, size_t count)
{
	ksu_handle_sys_read_fd(fd);
	return armeabi_read(fd, buf, count);
}

static void read_and_replace_syscall(void *old_ptr, unsigned long syscall_nr, void *new_ptr, void *target_table)
{
	// *old_ptr = READ_ONCE(*((void **)sys_call_table + syscall_nr));
	// WRITE_ONCE(*((void **)sys_call_table + syscall_nr), new_ptr);

	// the one from zx2c4 looks like above, but the issue is that we dont have 
	// READ_ONCE and WRITE_ONCE on 3.x kernels, here we just force volatile everything
	// since those are actually just forced-aligned-volatile-rw

	// void **syscall_addr = (void **)(sys_call_table + syscall_nr);
	// sugar: *(a + b) == a[b]; , a + b == &a[b];

	void **sctable = (void **)target_table;
	void **syscall_addr = (void **)&sctable[syscall_nr];

	// dont hook non-existing syscall
	if (!FORCE_VOLATILE(*syscall_addr))
		return;

	pr_info("%s: syscall: #%d slot: 0x%lx new_ptr: 0x%lx \n", __func__, syscall_nr, *(long *)syscall_addr, (long)new_ptr);

	barrier();
	*(void **)old_ptr = FORCE_VOLATILE(*syscall_addr);

	barrier();
	preempt_disable();
	FORCE_VOLATILE(*syscall_addr) = new_ptr;
	preempt_enable();

	flush_cache_all();
	smp_mb();

	return;
}

static int ksu_syscall_table_restore()
{
	set_user_nice(current, 19); // low prio

loop_start:

	msleep(1000);

	if (*(volatile bool *)&ksu_vfs_read_hook)
		goto loop_start;
	
	return 0;
}

static DEFINE_MUTEX(sucompat_toggle_mutex);

#if 0
static void syscall_table_sucompat_enable()
{
	mutex_lock(&sucompat_toggle_mutex);
	mutex_unlock(&sucompat_toggle_mutex);
}

static void syscall_table_sucompat_disable()
{
	mutex_lock(&sucompat_toggle_mutex);
	mutex_unlock(&sucompat_toggle_mutex);
}
#endif

static __init int ksu_syscall_table_hook_init()
{
	unsigned long *sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

	read_and_replace_syscall((void *)&armeabi_reboot, __ARMEABI_reboot, (void *)hook_armeabi_reboot, (void *)sys_call_table);

	read_and_replace_syscall((void *)&armeabi_execve, __ARMEABI_execve, (void *)hook_armeabi_execve, (void *)compat_sys_call_table);
	read_and_replace_syscall((void *)&armeabi_faccessat, __ARMEABI_faccessat, (void *)hook_armeabi_faccessat, (void *)compat_sys_call_table);
	read_and_replace_syscall((void *)&armeabi_fstatat64, __ARMEABI_fstatat64, (void *)hook_armeabi_fstatat64, (void *)compat_sys_call_table);

	kthread_run(ksu_syscall_table_restore, NULL, "unhook");
	return 0;
}
late_initcall(ksu_syscall_table_hook_init);

// EOF
