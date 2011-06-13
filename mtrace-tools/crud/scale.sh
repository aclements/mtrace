#!/bin/sh

if [ $# -ne "1" ]; then
    echo "usage: $0 dbname"
    exit 1
fi

labels="runqueues xtime_lock hrtimer_bases rcu_sched_state boot_tvec_bases irq_stack_union blkdev_queue wall_to_monotonic jiffies_64 clocksource_jiffies rcu_sched_state:rcu_node_level_0 timekeeper"

filterlabel=''
for label in $labels; do
    filterlabel="$filterlabel -filter-label $label"
done

filtertidcount='-filter-tid-count 2 -filter-cpu-count 2 -filter-cpu-percent 95'

./scale.py db/$1.db procy $filterlabel $filtertidcount
