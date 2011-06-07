#!/bin/sh

set -e

if [ $# -ne "1" ]; then
    echo "usage: $0 exim-type"
    exit 1
fi

name=$1

# xtime -- some false sharing!
# xtime_lock --
# jiffies_64 --
# clocksource_jiffies -- 

#
# "migration problems"
#
# hrtimer_bases -- migrate CPUs, have a struct hrtimer, the base of the timer
#  is for the previous CPU.  The base also acts as the head of a list.
# boot_tvec_bases -- similar to above
# task_xstate -- task FPU stuff..allocated on one CPU, task migrates, then 
#  touched on the other CPU
# kstat_irqs_all -- reading IRQ stats
# signal_cache -- allocated with the task_struct, touched during account_group_exec_runtime..
# __tracepoint_itimer_expire -- timer started on one core, processes moves to another?
# mm_struct -- warmup from running on new core


#
# "fact of life problems"
#
# TCP -- worker and server might run on different cores
# skbuff_fclone_cache -- same as TCP
# skbuff_head_cache -- same as TCP
# sched_group_phys -- load balancer, find lightest loaded cpu on sys_clone
# vm_area_struct -- setup on one CPU, accessed on another
# runqueues -- load balancer, write to TCP, wake up reading thread on other core
# shmem_inode_cache (an inode from /dev/shm) -- writing to the same file.  There are
#  a couple files.  One is probably the log.  The others might be written to by the
#  master (access clumps are far apart).  NOTE: __get_file_write_access weirdness!
# timekeeper -- global clock stuff, updated on core 0, read by other cores (some false sharing?!)
# cpu_hotplug - sched_setaffinity
# kstat -- /proc/stat stuff
# total_forks -- /proc/stat
# irq_stat -- /proc/stat
# inode_cache -- write to a shared file, mark it as dirty.
# blkdev_queue -- more writing to a shared file, marking it as dirty
# bdev_cache -- more writing to a shared file (goes into ext3 code, pulls looks up block?)
# buffer_head -- more writing to file (might just be warmup)
# rcu_sched_data -- ??
# rcu_sched_state -- ??
# mm_cachep -- slab cache rebalancing
# journal_handle -- slab cache rebalancing
# task_struct_cachep -- slab cache rebalancing (possibly false sharing?!)
# sighand_cache -- slab cache rebalancing
# shmem_inode_cachep -- slab cache rebalancing (possible false sharing?!)
# anon_vma_cachep -- possible false sharing?!
# fs_cachep -- slab cache rebalancing
# cred_jar -- possible false sharing?!
# signal_cachep -- possible false sharing?!
# raw_time -- shared monotonic posix clock
# radix_tree_node -- looks like cold misses?
# init_fs -- looks like cold miss during stat?
# files_cache -- looks like cold miss (possible false sharing!?)
# wall_to_monotonic -- smp_apic_timer_interrupt crap (false sharing, cold miss?)
# tick_length -- smp_apic_timer_interrupt crap (false sharing, cold miss?)
# calc_load_tasks -- periodic smp_apic_timer_interrupt crap
# calc_load_update -- periodic smp_apic_timer_interrupt crap
# rdwr_pipefifo_fops -- warmup?
# sched_clock_data -- wake up a remote thread, update some runqueue data.
# sigqueue -- warmup?
# task_struct -- it looks like most of these have to do with waking up a remote thread.

#
# "real problems"
#
# tasklist_lock
# inode_lock
# last_ino.31886 -- the last_inode allocated (we have a pk patch for this?)
# anon_vma_chain -- anon_vma_fork problem (false sharing?!)
# anon_vma -- similar problem as anon_vma_chain
# ext3_inode_cache -- i_writecount stuff during fork/exit, and some stuff during page fault
# filp -- a problem during fork/exit and during page faults
# arp_cache -- periodically time stamp confirmed responses from neighbours (it's never read...could make this per-cpu?)
# inode_in_use -- the global list of in use inodes (we have a pk patch for this?)
# pgd_list -- global list of page dirs, so they can be synchronized (make percpu).
# pgd_lock -- protects pgd_list (use the big lock, or what ever that's called)
# sock_inode_cache -- a bit in flags in cleared on one CPU, and a different bit is checked on 
#  another CPU (split bits into multiple flags, or conditional clear (clear iff not clear)
# tcp_memory_allocated -- tracks TCP memory usage (we have a pk patch for this?)
# vm_stat -- stats about NUMA allocations (hit in the desired zone, etc).  
#  Already implements a distributed counter like approach.  (could increase the stat_threshold)
# mnt_cache -- shared struct vfsmount stuff (sloppy counter pk patch?)
# rename_lock -- dcache rename lock
# kernel_flag -- kernel lock, used for posix file locks
# file_lock_cache -- meta data for a locked file.  add to list on one core, removed on another core)
# file_lock_list -- global list of locked files
# fasync_lock -- global lock for fasync (could probably make per-cpu)
# dcache_lock -- Yikes!
# init_pid_ns -- some sort of counter is modified and a bitmap.  (Could use approximate counters, but alloc_pidmap 
#  might be slow.  Avoid by using a different PID allocation scheme?)
# __userpte_alloc_gfp -- for allocating a user pte (false sharing?!)
# vm_committed_as -- more vm stats, usese per CPU counter, so probably not a real problem.
# init_nsproxy -- mostly ref. counting.  (could probably use sloppy counters).  Also appears to be some migration issues.
# init_task -- thread group leader is added to a list on the init_task.
# nr_threads -- global count of threads (we have a pk patch for this?)
# pid -- add and removing to a child (only group leaders?) to list in the parent's struct pid.
# dentry_stat -- global dentry stats (we have a pk patch for this)
# pidmap_lock -- protects a global pid_hash table
# root_user -- resource accouting during process creation (could probably use approximate counters)
# pid_max -- not really updated (looks like false sharing)
# rcu_bh_data -- false sharing?
# dentry -- the lookup, refcounting etc (we have pk patches?)
# ip_dst_cache -- some sort of dst ref. counting (could use sloppy counters)

#
# anon problems
#
# size-1024 
#  ffffffff81276f3d -- FOL, skbuf data buffer (written on one core, read on another)
#  ffffffff812806ed -- FOL, TCP acks (written on one core, read on another)
#  ffffffff810afe22 -- FOL, warmup, super block thing, possibly something with writing
#  ffffffff8110f394 -- FOL, warmup, something writing to EXT3
#  ffffffff8110f309 -- FOL, warmup, some sort of block alloc thing
# size-4096
#  ffffffff810a9279 -- slab rebalancing?
#  ffffffff81476702 -- PID bitmaps
# size-16384
#  ffffffff812d0c26 -- some funny timer thing, FOL?
# size-192
#  ffffffff810533af -- a funny groups.c thing that is always mucked with in rcutree.
# size-128
#  ffffffff810a9b82 -- FOL, cache alloc refill.
# size-64
#  ffffffff8123ff13 -- part of a socket inode (softirq does something on one core, sys_read is called on another core)
# size-32
#  ffffffff8110fad7 -- FOL, warmup, some sort of block alloc thing


labels="xtime xtime_lock jiffies_64 clocksource_jiffies hrtimer_bases boot_tvec_bases task_xstate kstat_irqs_all signal_cache __tracepoint_itimer_expire mm_struct"
fol_labels="TCP skbuff_fclone_cache sched_group_phys vm_area_struct runqueues shmem_inode_cache timekeeper cpu_hotplug skbuff_head_cache kstat total_forks irq_stat inode_cache blkdev_queue bdev_cache rcu_sched_data rcu_sched_state mm_cachep journal_handle task_struct_cachep sighand_cache pid shmem_inode_cachep raw_time anon_vma_chain radix_tree_node init_fs files_cache wall_to_monotonic tick_length calc_load_tasks calc_load_update anon_vma_cachep fs_cachep cred_jar signal_cachep rdwr_pipefifo_fops sched_clock_data sigqueue buffer_head task_struct size-16384 size-192 size-128 size-64"
problem_labels="tasklist_lock inode_lock last_ino.31886 anon_vma ext3_inode_cache filp arp_cache inode_in_use pgd_list pgd_lock sock_inode_cache tcp_memory_allocated vm_stat mnt_cache rename_lock kernel_flag fasync_lock dcache_lock init_pid_ns __userpte_alloc_gfp task_struct_cachep vm_committed_as init_nsproxy init_task nr_threads file_lock_cache file_lock_list dentry_stat pidmap_lock root_user pid_max rcu_bh_data dentry ip_dst_cache"

alloc_pcs="ffffffff81276f3d ffffffff812806ed ffffffff810a9279 ffffffff81476702 ffffffff810afe22 ffffffff8110f394 ffffffff8110f309 ffffffff8110fad7"

tmp="size-32 size-16384 size-64 size-192 size-4096 size-1024 size-128"

labels="$labels $problem_labels $fol_labels"
labels=""

#

filterlabel=''
for label in $labels; do
    filterlabel="$filterlabel -filterlabel $label"
done

filterpc=''
for pc in $alloc_pcs; do
    filterpc="$filterpc -filterpc $pc"
done

./summary.py exim-$name.db smtpbm $filterlabel $filterpc -numprint 999 > summary-exim-$name.out
cat summary-exim-$name.out
