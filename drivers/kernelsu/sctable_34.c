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

static void patch_sctable()
{
	void **sctable = (void **)kallsyms_lookup_name("sys_call_table");

//	void **syscall_addr = (void **)&sctable[syscall_nr];

	*(void **)&armeabi_reboot = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_reboot]);

	*(void **)&armeabi_execve = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_execve]);

	*(void **)&armeabi_faccessat = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_execve]);

	*(void **)&armeabi_fstatat64 = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_execve]);

	*(void **)&armeabi_fstat64 = FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_execve]);

	preempt_disable();

	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_reboot]) = hook_armeabi_reboot;

	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_execve]) = hook_armeabi_execve;

	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_faccessat]) = hook_armeabi_faccessat;

	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstatat64]) = hook_armeabi_fstatat64;

	FORCE_VOLATILE(*(void **)&sctable[__ARMEABI_fstat64]) = hook_armeabi_fstatat64;

	preempt_enable();

	flush_cache_all(); // this is important!
	smp_mb();

	return;
}

static __init int ksu_syscall_table_hook_init()
{
	patch_sctable();

	return 0;
}
arch_initcall(ksu_syscall_table_hook_init);

// EOF
