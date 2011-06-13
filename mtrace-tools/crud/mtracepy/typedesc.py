type_to_description = {
    'TCP' : 'Meta data for a single TCP connection',
    'skbuff_fclone_cache' : 'Packet data',
    'skbuff_head_cache' : 'Packet metadata',

    'sched_group_phys' : 'CPU load information',
    'vm_area_struct' : 'Virtual memory mapping metadata',
    'task_struct' : 'Task metadata',
    'runqueues' : 'Per-core thread run queues',
    'signal_cache' : 'Signal and process metadata',

    'jiffies_64' : 'Global monotically increasing count of elapsed time quantums',
    'xtime_lock' : 'Sequence lock protecting xtime',
    'xtime' : 'Global monotically increasing time',
    'clocksource_jiffies' : 'Global object for accessing a running hardware counter',
    'timekeeper' : 'Global object for managing the wall clock time',
    'hrtimer_bases' : 'Per-core high resolution timer metadata',
    'wall_to_monotonic' : 'Factor to convert xtime to wall clock time',
    'tick_length' : 'NTP metadata',

    'rcu_sched_data' : 'Per-core RCU metadata (quiescent and grace period management, etc)',
    'rcu_bh_data' : 'Per-core RCU metadata for bottom half mode (softirq, tasklets/workqueues?)',
    'rcu_sched_state' : 'Global RCU state',

    'dentry' : 'Directory entry metadata',
    'mnt_cache' : 'Mount point metadata',
    'shmem_inode_cache' : 'Inode metadata for tmpfs files',
    'ext3_inode_cache' : 'Inode metadata for ext3 files',
    'radix_tree_node' : 'Radix tree node and commonly used for the buffer cache',
    'filp' : 'File metadata',
    'fs_cache' : 'Per-thread file system root metadata',
    'files_cache' : 'Per-task file descriptor table',

    'blkdev_queue' : 'Per-block device request queue',

    'root_user' : 'Root user resource usuage statistics',
    'cred_jar' : 'Per-task security credentials',

    'size-1024' : 'Anonymouns 1024-byte memory allocation',
    'size-128' : 'Anonymous 128-byte memory allocation',
    '' : ''
}

type_to_category = {
    'TCP' : 'Fact of life'
}

class TypeDescription:
    def __init__(self, typeName, count = 0):
        self.typeName = typeName
        self.count = count

    def category(self):
        if self.typeName in type_to_category:
            return type_to_category[self.typeName]
        return '(Unknown)'

    def description(self):
        if self.typeName in type_to_description:
            return type_to_description[self.typeName]
        return '(Unknown)'
