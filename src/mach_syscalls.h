MACH_ERROR_SYSCALL(0)
MACH_ERROR_SYSCALL(1)
MACH_ERROR_SYSCALL(2)
MACH_ERROR_SYSCALL(3)
MACH_ERROR_SYSCALL(4)
MACH_ERROR_SYSCALL(5)
MACH_ERROR_SYSCALL(6)
MACH_ERROR_SYSCALL(7)
MACH_ERROR_SYSCALL(8)
MACH_ERROR_SYSCALL(9)
MACH_SYSCALL(_kernelrpc_mach_vm_allocate, 4, 10, passthrough)
MACH_ERROR_SYSCALL(11)
MACH_SYSCALL(_kernelrpc_mach_vm_deallocate, 3, 12, passthrough)
MACH_ERROR_SYSCALL(13)
MACH_SYSCALL(_kernelrpc_mach_vm_protect, 5, 14, passthrough)
MACH_SYSCALL(_kernelrpc_mach_vm_map, 6, 15, passthrough)
MACH_SYSCALL(_kernelrpc_mach_port_allocate, 3, 16, passthrough)
MACH_SYSCALL(_kernelrpc_mach_port_destroy, 2, 17, todo)
MACH_SYSCALL(_kernelrpc_mach_port_deallocate, 2, 18, passthrough)
MACH_SYSCALL(_kernelrpc_mach_port_mod_refs, 4, 19, passthrough)
MACH_SYSCALL(_kernelrpc_mach_port_move_member, 3, 20, passthrough)
MACH_SYSCALL(_kernelrpc_mach_port_insert_right, 4, 21, passthrough)
MACH_SYSCALL(_kernelrpc_mach_port_insert_member, 3, 22, passthrough)
MACH_SYSCALL(_kernelrpc_mach_port_extract_member, 3, 23, todo)
MACH_SYSCALL(_kernelrpc_mach_port_construct, 4, 24, passthrough)
MACH_SYSCALL(_kernelrpc_mach_port_destruct, 4, 25, passthrough)
MACH_SYSCALL(mach_reply_port, 0, 26, passthrough)
MACH_SYSCALL(thread_self, 0, 27, passthrough)
MACH_SYSCALL(task_self, 0, 28, passthrough)
MACH_SYSCALL(host_self, 0, 29, passthrough)
MACH_ERROR_SYSCALL(30)
MACH_SYSCALL(mach_msg, 7, 31, passthrough)
MACH_SYSCALL(mach_msg_overwrite, 8, 32, todo)
MACH_SYSCALL(semaphore_signal, 1, 33, passthrough)
MACH_SYSCALL(semaphore_signal_all, 1, 34, todo)
MACH_SYSCALL(semaphore_signal_thread, 2, 35, todo)
MACH_SYSCALL(semaphore_wait, 1, 36, passthrough)
MACH_SYSCALL(semaphore_wait_signal, 2, 37, todo)
MACH_SYSCALL(semaphore_timedwait, 3, 38, todo)
MACH_SYSCALL(semaphore_timedwait_signal, 4, 39, todo)
MACH_ERROR_SYSCALL(40)
MACH_SYSCALL(_kernelrpc_mach_port_guard, 4, 41, passthrough)
MACH_SYSCALL(_kernelrpc_mach_port_unguard, 3, 42, todo)
MACH_ERROR_SYSCALL(43)
MACH_SYSCALL(task_name_for_pid, 3, 44, todo)
MACH_SYSCALL(task_for_pid, 3, 45, todo)
MACH_SYSCALL(pid_for_task, 2, 46, todo)
MACH_ERROR_SYSCALL(47)
MACH_SYSCALL(macx_swapon, 4, 48, todo)
MACH_SYSCALL(macx_swapoff, 2, 49, todo)
MACH_ERROR_SYSCALL(50)
MACH_SYSCALL(macx_triggers, 4, 51, todo)
MACH_SYSCALL(macx_backing_store_suspend, 1, 52, todo)
MACH_SYSCALL(macx_backing_store_recovery, 1, 53, todo)
MACH_ERROR_SYSCALL(54)
MACH_ERROR_SYSCALL(55)
MACH_ERROR_SYSCALL(56)
MACH_ERROR_SYSCALL(57)
MACH_SYSCALL(pfz_exit, 0, 58, todo)
MACH_SYSCALL(swtch_pri, 0, 59, todo)
MACH_SYSCALL(swtch, 0, 60, todo)
MACH_SYSCALL(thread_switch, 3, 61, passthrough)
MACH_SYSCALL(clock_sleep, 5, 62, todo)
MACH_ERROR_SYSCALL(63)
MACH_ERROR_SYSCALL(64)
MACH_ERROR_SYSCALL(65)
MACH_ERROR_SYSCALL(66)
MACH_ERROR_SYSCALL(67)
MACH_ERROR_SYSCALL(68)
MACH_ERROR_SYSCALL(69)
MACH_ERROR_SYSCALL(70)
MACH_ERROR_SYSCALL(71)
MACH_ERROR_SYSCALL(72)
MACH_ERROR_SYSCALL(73)
MACH_ERROR_SYSCALL(74)
MACH_ERROR_SYSCALL(75)
MACH_ERROR_SYSCALL(76)
MACH_ERROR_SYSCALL(77)
MACH_ERROR_SYSCALL(78)
MACH_ERROR_SYSCALL(79)
MACH_ERROR_SYSCALL(80)
MACH_ERROR_SYSCALL(81)
MACH_ERROR_SYSCALL(82)
MACH_ERROR_SYSCALL(83)
MACH_ERROR_SYSCALL(84)
MACH_ERROR_SYSCALL(85)
MACH_ERROR_SYSCALL(86)
MACH_ERROR_SYSCALL(87)
MACH_ERROR_SYSCALL(88)
MACH_SYSCALL(mach_timebase_info, 1, 89, passthrough)
MACH_SYSCALL(mach_wait_until, 1, 90, todo)
MACH_SYSCALL(mk_timer_create, 0, 91, passthrough)
MACH_SYSCALL(mk_timer_destroy, 1, 92, todo)
MACH_SYSCALL(mk_timer_arm, 2, 93, passthrough)
MACH_SYSCALL(mk_timer_cancel, 2, 94, todo)
MACH_ERROR_SYSCALL(95)
MACH_ERROR_SYSCALL(96)
MACH_ERROR_SYSCALL(97)
MACH_ERROR_SYSCALL(98)
MACH_ERROR_SYSCALL(99)
MACH_SYSCALL(iokit_user_client, 8, 100, todo)
MACH_ERROR_SYSCALL(101)
MACH_ERROR_SYSCALL(102)
MACH_ERROR_SYSCALL(103)
MACH_ERROR_SYSCALL(104)
MACH_ERROR_SYSCALL(105)
MACH_ERROR_SYSCALL(106)
MACH_ERROR_SYSCALL(107)
MACH_ERROR_SYSCALL(108)
MACH_ERROR_SYSCALL(109)
MACH_ERROR_SYSCALL(110)
MACH_ERROR_SYSCALL(111)
MACH_ERROR_SYSCALL(112)
MACH_ERROR_SYSCALL(113)
MACH_ERROR_SYSCALL(114)
MACH_ERROR_SYSCALL(115)
MACH_ERROR_SYSCALL(116)
MACH_ERROR_SYSCALL(117)
MACH_ERROR_SYSCALL(118)
MACH_ERROR_SYSCALL(119)
MACH_ERROR_SYSCALL(120)
MACH_ERROR_SYSCALL(121)
MACH_ERROR_SYSCALL(122)
MACH_ERROR_SYSCALL(123)
MACH_ERROR_SYSCALL(124)
MACH_ERROR_SYSCALL(125)
MACH_ERROR_SYSCALL(126)
MACH_ERROR_SYSCALL(127)
