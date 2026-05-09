#ifndef CONFIG_ARM
#error "only meant for ARM"
#endif

// ref: https://elixir.bootlin.com/linux/v4.14.1/source/include/uapi/asm-generic/unistd.h
// ref: https://elixir.bootlin.com/linux/v4.14.1/source/arch/arm64/include/asm/unistd32.h
// ref: https://elixir.bootlin.com/linux/v4.14.1/source/arch/arm64/include/asm/unistd.h

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

#include <asm/cacheflush.h>
#include <asm/pgtable.h>

void patch_table(void)
{

	unsigned long *sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

	pr_info("sys_reboot: 0x%lx \n", (uintptr_t)(void *)sys_call_table[__ARMEABI_reboot]);

	armeabi_reboot = (void *)sys_call_table[__ARMEABI_reboot];

	pr_info("armeabi_reboot: 0x%lx \n", (uintptr_t)armeabi_reboot);

	sys_call_table[__ARMEABI_reboot] = (unsigned long)armeabi_reboot;

	pr_info("sys_reboot: 0x%lx \n", (uintptr_t)(void *)sys_call_table[__ARMEABI_reboot]);

	flush_cache_all();
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

	patch_table();

	kthread_run(ksu_syscall_table_restore, NULL, "unhook");
	return 0;
}
late_initcall(ksu_syscall_table_hook_init);

// EOF
