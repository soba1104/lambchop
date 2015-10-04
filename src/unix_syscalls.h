UNIX_SYSCALL(syscall, 0, todo)
UNIX_SYSCALL(exit, 1, todo)
UNIX_SYSCALL(fork, 2, todo)
UNIX_SYSCALL(read, 3, passthrough)
UNIX_SYSCALL(write, 4, passthrough)
UNIX_SYSCALL(open, 5, open)
UNIX_SYSCALL(close, 6, passthrough)
UNIX_SYSCALL(wait4, 7, todo)
UNIX_OLD_SYSCALL(creat, 8)
UNIX_SYSCALL(link, 9, todo)
UNIX_SYSCALL(unlink, 10, todo)
UNIX_OLD_SYSCALL(execv, 11)
UNIX_SYSCALL(chdir, 12, todo)
UNIX_SYSCALL(fchdir, 13, todo)
UNIX_SYSCALL(mknod, 14, todo)
UNIX_SYSCALL(chmod, 15, todo)
UNIX_SYSCALL(chown, 16, todo)
UNIX_OLD_SYSCALL(break, 17)
UNIX_SYSCALL(getfsstat, 18, todo)
UNIX_OLD_SYSCALL(lseek, 19)
UNIX_SYSCALL(getpid, 20, passthrough)
UNIX_OLD_SYSCALL(mount, 21)
UNIX_OLD_SYSCALL(umount, 22)
UNIX_SYSCALL(setuid, 23, todo)
UNIX_SYSCALL(getuid, 24, passthrough)
UNIX_SYSCALL(geteuid, 25, passthrough)
UNIX_SYSCALL(ptrace, 26, todo)
UNIX_SYSCALL(recvmsg, 27, todo)
UNIX_SYSCALL(sendmsg, 28, todo)
UNIX_SYSCALL(recvfrom, 29, todo)
UNIX_SYSCALL(accept, 30, passthrough)
UNIX_SYSCALL(getpeername, 31, todo)
UNIX_SYSCALL(getsockname, 32, todo)
UNIX_SYSCALL(access, 33, passthrough)
UNIX_SYSCALL(chflags, 34, todo)
UNIX_SYSCALL(fchflags, 35, todo)
UNIX_SYSCALL(sync, 36, todo)
UNIX_SYSCALL(kill, 37, todo)
UNIX_OLD_SYSCALL(stat, 38)
UNIX_SYSCALL(getppid, 39, todo)
UNIX_OLD_SYSCALL(lstat, 40)
UNIX_SYSCALL(dup, 41, todo)
UNIX_SYSCALL(pipe, 42, passthrough)
UNIX_SYSCALL(getegid, 43, passthrough)
UNIX_OLD_SYSCALL(profil, 44)
UNIX_OLD_SYSCALL(ktrace, 45)
UNIX_SYSCALL(sigaction, 46, sigaction)
UNIX_SYSCALL(getgid, 47, passthrough)
UNIX_SYSCALL(sigprocmask, 48, todo)
UNIX_SYSCALL(getlogin, 49, todo)
UNIX_SYSCALL(setlogin, 50, todo)
UNIX_SYSCALL(acct, 51, todo)
UNIX_SYSCALL(sigpending, 52, todo)
UNIX_SYSCALL(sigaltstack, 53, todo)
UNIX_SYSCALL(ioctl, 54, passthrough)
UNIX_SYSCALL(reboot, 55, todo)
UNIX_SYSCALL(revoke, 56, todo)
UNIX_SYSCALL(symlink, 57, todo)
UNIX_SYSCALL(readlink, 58, todo)
UNIX_SYSCALL(execve, 59, todo)
UNIX_SYSCALL(umask, 60, todo)
UNIX_SYSCALL(chroot, 61, todo)
UNIX_OLD_SYSCALL(fstat, 62)
UNIX_ERROR_SYSCALL(63)
UNIX_OLD_SYSCALL(getpagesize, 64)
UNIX_SYSCALL(msync, 65, todo)
UNIX_SYSCALL(vfork, 66, todo)
UNIX_OLD_SYSCALL(vread, 67)
UNIX_OLD_SYSCALL(vwrite, 68)
UNIX_OLD_SYSCALL(sbrk, 69)
UNIX_OLD_SYSCALL(sstk, 70)
UNIX_OLD_SYSCALL(mmap, 71)
UNIX_OLD_SYSCALL(vadvise, 72)
UNIX_SYSCALL(munmap, 73, passthrough)
UNIX_SYSCALL(mprotect, 74, passthrough)
UNIX_SYSCALL(madvise, 75, passthrough)
UNIX_OLD_SYSCALL(vhangup, 76)
UNIX_OLD_SYSCALL(vlimit, 77)
UNIX_SYSCALL(mincore, 78, todo)
UNIX_SYSCALL(getgroups, 79, todo)
UNIX_SYSCALL(setgroups, 80, todo)
UNIX_SYSCALL(getpgrp, 81, todo)
UNIX_SYSCALL(setpgid, 82, todo)
UNIX_SYSCALL(setitimer, 83, todo)
UNIX_OLD_SYSCALL(wait, 84)
UNIX_SYSCALL(swapon, 85, todo)
UNIX_SYSCALL(getitimer, 86, todo)
UNIX_OLD_SYSCALL(gethostname, 87)
UNIX_OLD_SYSCALL(sethostname, 88)
UNIX_SYSCALL(getdtablesize, 89, todo)
UNIX_SYSCALL(dup2, 90, todo)
UNIX_OLD_SYSCALL(getdopt, 91)
UNIX_SYSCALL(fcntl, 92, passthrough)
UNIX_SYSCALL(select, 93, passthrough)
UNIX_OLD_SYSCALL(setdopt, 94)
UNIX_SYSCALL(fsync, 95, todo)
UNIX_SYSCALL(setpriority, 96, todo)
UNIX_SYSCALL(socket, 97, passthrough)
UNIX_SYSCALL(connect, 98, todo)
UNIX_OLD_SYSCALL(accept, 99)
UNIX_SYSCALL(getpriority, 100, todo)
UNIX_OLD_SYSCALL(send, 101)
UNIX_OLD_SYSCALL(recv, 102)
UNIX_OLD_SYSCALL(sigreturn, 103)
UNIX_SYSCALL(bind, 104, passthrough)
UNIX_SYSCALL(setsockopt, 105, todo)
UNIX_SYSCALL(listen, 106, passthrough)
UNIX_OLD_SYSCALL(vtimes, 107)
UNIX_OLD_SYSCALL(sigvec, 108)
UNIX_OLD_SYSCALL(sigblock, 109)
UNIX_OLD_SYSCALL(sigsetmask, 110)
UNIX_SYSCALL(sigsuspend, 111, todo)
UNIX_OLD_SYSCALL(sigstack, 112)
UNIX_OLD_SYSCALL(recvmsg, 113)
UNIX_OLD_SYSCALL(sendmsg, 114)
UNIX_OLD_SYSCALL(vtrace, 115)
UNIX_SYSCALL(gettimeofday, 116, todo)
UNIX_SYSCALL(getrusage, 117, todo)
UNIX_SYSCALL(getsockopt, 118, todo)
UNIX_OLD_SYSCALL(resuba, 119)
UNIX_SYSCALL(readv, 120, todo)
UNIX_SYSCALL(writev, 121, todo)
UNIX_SYSCALL(settimeofday, 122, todo)
UNIX_SYSCALL(fchown, 123, todo)
UNIX_SYSCALL(fchmod, 124, todo)
UNIX_OLD_SYSCALL(recvfrom, 125)
UNIX_SYSCALL(setreuid, 126, todo)
UNIX_SYSCALL(setregid, 127, todo)
UNIX_SYSCALL(rename, 128, todo)
UNIX_OLD_SYSCALL(truncate, 129)
UNIX_OLD_SYSCALL(ftruncate, 130)
UNIX_SYSCALL(flock, 131, todo)
UNIX_SYSCALL(mkfifo, 132, todo)
UNIX_SYSCALL(sendto, 133, todo)
UNIX_SYSCALL(shutdown, 134, todo)
UNIX_SYSCALL(socketpair, 135, todo)
UNIX_SYSCALL(mkdir, 136, todo)
UNIX_SYSCALL(rmdir, 137, todo)
UNIX_SYSCALL(utimes, 138, todo)
UNIX_SYSCALL(futimes, 139, todo)
UNIX_SYSCALL(adjtime, 140, todo)
UNIX_OLD_SYSCALL(getpeername, 141)
UNIX_SYSCALL(gethostuuid, 142, todo)
UNIX_OLD_SYSCALL(sethostid, 143)
UNIX_OLD_SYSCALL(getrlimit, 144)
UNIX_OLD_SYSCALL(setrlimit, 145)
UNIX_OLD_SYSCALL(killpg, 146)
UNIX_SYSCALL(setsid, 147, todo)
UNIX_OLD_SYSCALL(setquota, 148)
UNIX_OLD_SYSCALL(qquota, 149)
UNIX_OLD_SYSCALL(getsockname, 150)
UNIX_SYSCALL(getpgid, 151, todo)
UNIX_SYSCALL(setprivexec, 152, todo)
UNIX_SYSCALL(pread, 153, passthrough)
UNIX_SYSCALL(pwrite, 154, todo)
UNIX_SYSCALL(nfssvc, 155, todo)
UNIX_OLD_SYSCALL(getdirentries, 156)
UNIX_SYSCALL(statfs, 157, todo)
UNIX_SYSCALL(fstatfs, 158, todo)
UNIX_SYSCALL(unmount, 159, todo)
UNIX_OLD_SYSCALL(async_daemon, 160)
UNIX_SYSCALL(getfh, 161, todo)
UNIX_OLD_SYSCALL(getdomainname, 162)
UNIX_OLD_SYSCALL(setdomainname, 163)
UNIX_ERROR_SYSCALL(164)
UNIX_SYSCALL(quotactl, 165, todo)
UNIX_OLD_SYSCALL(exportfs, 166)
UNIX_SYSCALL(mount, 167, todo)
UNIX_OLD_SYSCALL(ustat, 168)
UNIX_SYSCALL(csops, 169, passthrough) // cs means code signing
UNIX_SYSCALL(csops_audittoken, 170, todo)
UNIX_OLD_SYSCALL(wait3, 171)
UNIX_OLD_SYSCALL(rpause, 172)
UNIX_SYSCALL(waitid, 173, todo)
UNIX_OLD_SYSCALL(getdents, 174)
UNIX_OLD_SYSCALL(gc_control, 175)
UNIX_OLD_SYSCALL(add_profil, 176)
UNIX_ERROR_SYSCALL(177)
UNIX_ERROR_SYSCALL(178)
UNIX_SYSCALL(kdebug_trace64, 179, todo)
UNIX_SYSCALL(kdebug_trace, 180, todo)
UNIX_SYSCALL(setgid, 181, todo)
UNIX_SYSCALL(setegid, 182, todo)
UNIX_SYSCALL(seteuid, 183, todo)
UNIX_SYSCALL(sigreturn, 184, todo)
UNIX_SYSCALL(chud, 185, todo)
UNIX_ERROR_SYSCALL(186)
UNIX_SYSCALL(fdatasync, 187, todo)
UNIX_SYSCALL(stat, 188, todo)
UNIX_SYSCALL(fstat, 189, todo)
UNIX_SYSCALL(lstat, 190, todo)
UNIX_SYSCALL(pathconf, 191, todo)
UNIX_SYSCALL(fpathconf, 192, todo)
UNIX_ERROR_SYSCALL(193)
UNIX_SYSCALL(getrlimit, 194, passthrough)
UNIX_SYSCALL(setrlimit, 195, todo)
UNIX_SYSCALL(getdirentries, 196, todo)
UNIX_SYSCALL(mmap, 197, mmap)
UNIX_SYSCALL(__syscall, 198, todo)
UNIX_SYSCALL(lseek, 199, todo)
UNIX_SYSCALL(truncate, 200, todo)
UNIX_SYSCALL(ftruncate, 201, todo)
UNIX_SYSCALL(sysctl, 202, passthrough)
UNIX_SYSCALL(mlock, 203, todo)
UNIX_SYSCALL(munlock, 204, todo)
UNIX_SYSCALL(undelete, 205, todo)
UNIX_OLD_SYSCALL(ATsocket, 206)
UNIX_OLD_SYSCALL(ATgetmsg, 207)
UNIX_OLD_SYSCALL(ATputmsg, 208)
UNIX_OLD_SYSCALL(ATsndreq, 209)
UNIX_OLD_SYSCALL(ATsndrsp, 210)
UNIX_OLD_SYSCALL(ATgetreq, 211)
UNIX_OLD_SYSCALL(ATgetrsp, 212)
UNIX_ERROR_SYSCALL(213)
UNIX_ERROR_SYSCALL(214)
UNIX_ERROR_SYSCALL(215)
UNIX_SYSCALL(open_dprotected_np, 216, todo)
UNIX_ERROR_SYSCALL(217)
UNIX_ERROR_SYSCALL(218)
UNIX_ERROR_SYSCALL(219)
UNIX_SYSCALL(getattrlist, 220, passthrough)
UNIX_SYSCALL(setattrlist, 221, todo)
UNIX_SYSCALL(getdirentriesattr, 222, todo)
UNIX_SYSCALL(exchangedata, 223, todo)
UNIX_OLD_SYSCALL(checkuseraccess_fsgetpath, 224)
UNIX_SYSCALL(searchfs, 225, todo)
UNIX_SYSCALL(delete, 226, todo)
UNIX_SYSCALL(copyfile, 227, todo)
UNIX_SYSCALL(fgetattrlist, 228, todo)
UNIX_SYSCALL(fsetattrlist, 229, todo)
UNIX_SYSCALL(poll, 230, todo)
UNIX_SYSCALL(watchevent, 231, todo)
UNIX_SYSCALL(waitevent, 232, todo)
UNIX_SYSCALL(modwatch, 233, todo)
UNIX_SYSCALL(getxattr, 234, todo)
UNIX_SYSCALL(fgetxattr, 235, todo)
UNIX_SYSCALL(setxattr, 236, todo)
UNIX_SYSCALL(fsetxattr, 237, todo)
UNIX_SYSCALL(removexattr, 238, todo)
UNIX_SYSCALL(fremovexattr, 239, todo)
UNIX_SYSCALL(listxattr, 240, todo)
UNIX_SYSCALL(flistxattr, 241, todo)
UNIX_SYSCALL(fsctl, 242, todo)
UNIX_SYSCALL(initgroups, 243, todo)
UNIX_SYSCALL(posix_spawn, 244, todo)
UNIX_SYSCALL(ffsctl, 245, todo)
UNIX_ERROR_SYSCALL(246)
UNIX_SYSCALL(nfsclnt, 247, todo)
UNIX_SYSCALL(fhopen, 248, todo)
UNIX_ERROR_SYSCALL(249)
UNIX_SYSCALL(minherit, 250, todo)
UNIX_SYSCALL(semsys, 251, todo)
UNIX_SYSCALL(msgsys, 252, todo)
UNIX_SYSCALL(shmsys, 253, todo)
UNIX_SYSCALL(semctl, 254, todo)
UNIX_SYSCALL(semget, 255, todo)
UNIX_SYSCALL(semop, 256, todo)
UNIX_ERROR_SYSCALL(257)
UNIX_SYSCALL(msgctl, 258, todo)
UNIX_SYSCALL(msgget, 259, todo)
UNIX_SYSCALL(msgsnd, 260, todo)
UNIX_SYSCALL(msgrcv, 261, todo)
UNIX_SYSCALL(shmat, 262, todo)
UNIX_SYSCALL(shmctl, 263, todo)
UNIX_SYSCALL(shmdt, 264, todo)
UNIX_SYSCALL(shmget, 265, todo)
UNIX_SYSCALL(shm_open, 266, todo)
UNIX_SYSCALL(shm_unlink, 267, todo)
UNIX_SYSCALL(sem_open, 268, todo)
UNIX_SYSCALL(sem_close, 269, todo)
UNIX_SYSCALL(sem_unlink, 270, todo)
UNIX_SYSCALL(sem_wait, 271, todo)
UNIX_SYSCALL(sem_trywait, 272, todo)
UNIX_SYSCALL(sem_post, 273, todo)
UNIX_SYSCALL(sysctlbyname, 274, todo)
UNIX_OLD_SYSCALL(sem_init, 275)
UNIX_OLD_SYSCALL(sem_destroy, 276)
UNIX_SYSCALL(open_extended, 277, todo)
UNIX_SYSCALL(umask_extended, 278, todo)
UNIX_SYSCALL(stat_extended, 279, todo)
UNIX_SYSCALL(lstat_extended, 280, todo)
UNIX_SYSCALL(fstat_extended, 281, todo)
UNIX_SYSCALL(chmod_extended, 282, todo)
UNIX_SYSCALL(fchmod_extended, 283, todo)
UNIX_SYSCALL(access_extended, 284, todo)
UNIX_SYSCALL(settid, 285, todo)
UNIX_SYSCALL(gettid, 286, todo)
UNIX_SYSCALL(setsgroups, 287, todo)
UNIX_SYSCALL(getsgroups, 288, todo)
UNIX_SYSCALL(setwgroups, 289, todo)
UNIX_SYSCALL(getwgroups, 290, todo)
UNIX_SYSCALL(mkfifo_extended, 291, todo)
UNIX_SYSCALL(mkdir_extended, 292, todo)
UNIX_SYSCALL(identitysvc, 293, todo)
UNIX_SYSCALL(shared_region_check_np, 294, todo)
UNIX_OLD_SYSCALL(shared_region_map_np, 295)
UNIX_SYSCALL(vm_pressure_monitor, 296, todo)
UNIX_SYSCALL(psynch_rw_longrdlock, 297, todo)
UNIX_SYSCALL(psynch_rw_yieldwrlock, 298, todo)
UNIX_SYSCALL(psynch_rw_downgrade, 299, todo)
UNIX_SYSCALL(psynch_rw_upgrade, 300, todo)
UNIX_SYSCALL(psynch_mutexwait, 301, passthrough)
UNIX_SYSCALL(psynch_mutexdrop, 302, passthrough)
UNIX_SYSCALL(psynch_cvbroad, 303, todo)
UNIX_SYSCALL(psynch_cvsignal, 304, passthrough)
UNIX_SYSCALL(psynch_cvwait, 305, passthrough)
UNIX_SYSCALL(psynch_rw_rdlock, 306, todo)
UNIX_SYSCALL(psynch_rw_wrlock, 307, todo)
UNIX_SYSCALL(psynch_rw_unlock, 308, todo)
UNIX_SYSCALL(psynch_rw_unlock2, 309, todo)
UNIX_SYSCALL(getsid, 310, todo)
UNIX_SYSCALL(settid_with_pid, 311, todo)
UNIX_SYSCALL(psynch_cvclrprepost, 312, todo)
UNIX_SYSCALL(aio_fsync, 313, todo)
UNIX_SYSCALL(aio_return, 314, todo)
UNIX_SYSCALL(aio_suspend, 315, todo)
UNIX_SYSCALL(aio_cancel, 316, todo)
UNIX_SYSCALL(aio_error, 317, todo)
UNIX_SYSCALL(aio_read, 318, todo)
UNIX_SYSCALL(aio_write, 319, todo)
UNIX_SYSCALL(lio_listio, 320, todo)
UNIX_OLD_SYSCALL(__pthread_cond_wait, 321)
UNIX_SYSCALL(iopolicysys, 322, todo)
UNIX_SYSCALL(process_policy, 323, todo)
UNIX_SYSCALL(mlockall, 324, todo)
UNIX_SYSCALL(munlockall, 325, todo)
UNIX_ERROR_SYSCALL(326)
UNIX_SYSCALL(issetugid, 327, passthrough)
UNIX_SYSCALL(__pthread_kill, 328, todo)
UNIX_SYSCALL(__pthread_sigmask, 329, todo)
UNIX_SYSCALL(__sigwait, 330, todo)
UNIX_SYSCALL(__disable_threadsignal, 331, passthrough)
UNIX_SYSCALL(__pthread_markcancel, 332, todo)
UNIX_SYSCALL(__pthread_canceled, 333, todo)
UNIX_SYSCALL(__semwait_signal, 334, todo)
UNIX_OLD_SYSCALL(utrace, 335)
UNIX_SYSCALL(proc_info, 336, todo)
UNIX_SYSCALL(sendfile, 337, todo)
UNIX_SYSCALL(stat64, 338, passthrough)
UNIX_SYSCALL(fstat64, 339, passthrough)
UNIX_SYSCALL(lstat64, 340, passthrough)
UNIX_SYSCALL(stat64_extended, 341, todo)
UNIX_SYSCALL(lstat64_extended, 342, todo)
UNIX_SYSCALL(fstat64_extended, 343, todo)
UNIX_SYSCALL(getdirentries64, 344, passthrough)
UNIX_SYSCALL(statfs64, 345, todo)
UNIX_SYSCALL(fstatfs64, 346, passthrough)
UNIX_SYSCALL(getfsstat64, 347, todo)
UNIX_SYSCALL(__pthread_chdir, 348, todo)
UNIX_SYSCALL(__pthread_fchdir, 349, todo)
UNIX_SYSCALL(audit, 350, todo)
UNIX_SYSCALL(auditon, 351, todo)
UNIX_ERROR_SYSCALL(352)
UNIX_SYSCALL(getauid, 353, todo)
UNIX_SYSCALL(setauid, 354, todo)
UNIX_OLD_SYSCALL(getaudit, 355)
UNIX_OLD_SYSCALL(setaudit, 356)
UNIX_SYSCALL(getaudit_addr, 357, todo)
UNIX_SYSCALL(setaudit_addr, 358, todo)
UNIX_SYSCALL(auditctl, 359, todo)
UNIX_SYSCALL(bsdthread_create, 360, bsdthread_create)
UNIX_SYSCALL(bsdthread_terminate, 361, todo)
UNIX_SYSCALL(kqueue, 362, todo)
UNIX_SYSCALL(kevent, 363, todo)
UNIX_SYSCALL(lchown, 364, todo)
UNIX_SYSCALL(stack_snapshot, 365, todo)
UNIX_SYSCALL(bsdthread_register, 366, bsdthread_register)
UNIX_SYSCALL(workq_open, 367, todo)
UNIX_SYSCALL(workq_kernreturn, 368, todo)
UNIX_SYSCALL(kevent64, 369, todo)
UNIX_SYSCALL(__old_semwait_signal, 370, todo)
UNIX_SYSCALL(__old_semwait_signal_nocancel, 371, todo)
UNIX_SYSCALL(thread_selfid, 372, passthrough)
UNIX_SYSCALL(ledger, 373, todo)
UNIX_ERROR_SYSCALL(374)
UNIX_ERROR_SYSCALL(375)
UNIX_ERROR_SYSCALL(376)
UNIX_ERROR_SYSCALL(377)
UNIX_ERROR_SYSCALL(378)
UNIX_ERROR_SYSCALL(379)
UNIX_SYSCALL(__mac_execve, 380, todo)
UNIX_SYSCALL(__mac_syscall, 381, todo)
UNIX_SYSCALL(__mac_get_file, 382, todo)
UNIX_SYSCALL(__mac_set_file, 383, todo)
UNIX_SYSCALL(__mac_get_link, 384, todo)
UNIX_SYSCALL(__mac_set_link, 385, todo)
UNIX_SYSCALL(__mac_get_proc, 386, todo)
UNIX_SYSCALL(__mac_set_proc, 387, todo)
UNIX_SYSCALL(__mac_get_fd, 388, todo)
UNIX_SYSCALL(__mac_set_fd, 389, todo)
UNIX_SYSCALL(__mac_get_pid, 390, todo)
UNIX_SYSCALL(__mac_get_lcid, 391, todo)
UNIX_SYSCALL(__mac_get_lctx, 392, todo)
UNIX_SYSCALL(__mac_set_lctx, 393, todo)
UNIX_SYSCALL(setlcid, 394, todo)
UNIX_SYSCALL(getlcid, 395, todo)
UNIX_SYSCALL(read_nocancel, 396, passthrough)
UNIX_SYSCALL(write_nocancel, 397, passthrough)
UNIX_SYSCALL(open_nocancel, 398, passthrough)
UNIX_SYSCALL(close_nocancel, 399, passthrough)
UNIX_SYSCALL(wait4_nocancel, 400, todo)
UNIX_SYSCALL(recvmsg_nocancel, 401, todo)
UNIX_SYSCALL(sendmsg_nocancel, 402, todo)
UNIX_SYSCALL(recvfrom_nocancel, 403, todo)
UNIX_SYSCALL(accept_nocancel, 404, todo)
UNIX_SYSCALL(msync_nocancel, 405, todo)
UNIX_SYSCALL(fcntl_nocancel, 406, todo)
UNIX_SYSCALL(select_nocancel, 407, todo)
UNIX_SYSCALL(fsync_nocancel, 408, todo)
UNIX_SYSCALL(connect_nocancel, 409, todo)
UNIX_SYSCALL(sigsuspend_nocancel, 410, todo)
UNIX_SYSCALL(readv_nocancel, 411, todo)
UNIX_SYSCALL(writev_nocancel, 412, todo)
UNIX_SYSCALL(sendto_nocancel, 413, todo)
UNIX_SYSCALL(pread_nocancel, 414, todo)
UNIX_SYSCALL(pwrite_nocancel, 415, todo)
UNIX_SYSCALL(waitid_nocancel, 416, todo)
UNIX_SYSCALL(poll_nocancel, 417, todo)
UNIX_SYSCALL(msgsnd_nocancel, 418, todo)
UNIX_SYSCALL(msgrcv_nocancel, 419, todo)
UNIX_SYSCALL(sem_wait_nocancel, 420, todo)
UNIX_SYSCALL(aio_suspend_nocancel, 421, todo)
UNIX_SYSCALL(__sigwait_nocancel, 422, todo)
UNIX_SYSCALL(__semwait_signal_nocancel, 423, todo)
UNIX_SYSCALL(__mac_mount, 424, todo)
UNIX_SYSCALL(__mac_get_mount, 425, todo)
UNIX_SYSCALL(__mac_getfsstat, 426, todo)
UNIX_SYSCALL(fsgetpath, 427, todo)
UNIX_SYSCALL(audit_session_self, 428, todo)
UNIX_SYSCALL(audit_session_join, 429, todo)
UNIX_SYSCALL(fileport_makeport, 430, todo)
UNIX_SYSCALL(fileport_makefd, 431, todo)
UNIX_SYSCALL(audit_session_port, 432, todo)
UNIX_SYSCALL(pid_suspend, 433, todo)
UNIX_SYSCALL(pid_resume, 434, todo)
UNIX_SYSCALL(pid_hibernate, 435, todo)
UNIX_SYSCALL(pid_shutdown_sockets, 436, todo)
UNIX_OLD_SYSCALL(shared_region_slide_np, 437)
UNIX_SYSCALL(shared_region_map_and_slide_np, 438, todo)
UNIX_SYSCALL(kas_info, 439, todo)
UNIX_SYSCALL(memorystatus_control, 440, todo)
UNIX_SYSCALL(guarded_open_np, 441, todo)
UNIX_SYSCALL(guarded_close_np, 442, todo)
UNIX_SYSCALL(guarded_kqueue_np, 443, todo)
UNIX_SYSCALL(change_fdguard_np, 444, todo)
UNIX_OLD_SYSCALL(__proc_suppress, 445)
UNIX_SYSCALL(proc_rlimit_control, 446, todo)
UNIX_SYSCALL(connectx, 447, todo)
UNIX_SYSCALL(disconnectx, 448, todo)
UNIX_SYSCALL(peeloff, 449, todo)
UNIX_SYSCALL(socket_delegate, 450, todo)
UNIX_SYSCALL(telemetry, 451, todo)
UNIX_SYSCALL(proc_uuid_policy, 452, todo)
UNIX_SYSCALL(memorystatus_get_level, 453, todo)
UNIX_SYSCALL(system_override, 454, todo)
UNIX_SYSCALL(vfs_purge, 455, todo)
UNIX_SYSCALL(sfi_ctl, 456, todo)
UNIX_SYSCALL(sfi_pidctl, 457, todo)
UNIX_SYSCALL(coalition, 458, todo)
UNIX_SYSCALL(coalition_info, 459, todo)
UNIX_SYSCALL(necp_match_policy, 460, todo)
UNIX_SYSCALL(getattrlistbulk, 461, todo)
UNIX_ERROR_SYSCALL(462)
UNIX_SYSCALL(openat, 463, todo)
UNIX_SYSCALL(openat_nocancel, 464, todo)
UNIX_SYSCALL(renameat, 465, todo)
UNIX_SYSCALL(faccessat, 466, todo)
UNIX_SYSCALL(fchmodat, 467, todo)
UNIX_SYSCALL(fchownat, 468, todo)
UNIX_SYSCALL(fstatat, 469, todo)
UNIX_SYSCALL(fstatat64, 470, todo)
UNIX_SYSCALL(linkat, 471, todo)
UNIX_SYSCALL(unlinkat, 472, todo)
UNIX_SYSCALL(readlinkat, 473, todo)
UNIX_SYSCALL(symlinkat, 474, todo)
UNIX_SYSCALL(mkdirat, 475, todo)
UNIX_SYSCALL(getattrlistat, 476, todo)
UNIX_SYSCALL(proc_trace_log, 477, todo)
UNIX_SYSCALL(bsdthread_ctl, 478, passthrough)
UNIX_SYSCALL(openbyid_np, 479, todo)
UNIX_SYSCALL(recvmsg_x, 480, todo)
UNIX_SYSCALL(sendmsg_x, 481, todo)
UNIX_SYSCALL(thread_selfusage, 482, todo)
UNIX_SYSCALL(csrctl, 483, todo)
UNIX_SYSCALL(guarded_open_dprotected_np, 484, todo)
UNIX_SYSCALL(guarded_write_np, 485, todo)
UNIX_SYSCALL(guarded_pwrite_np, 486, todo)
UNIX_SYSCALL(guarded_writev_np, 487, todo)
UNIX_SYSCALL(rename_ext, 488, todo)
UNIX_SYSCALL(mremap_encrypted, 489, todo)
