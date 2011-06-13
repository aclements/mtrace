#!/bin/sh

if [ $# -ne "4" ]; then
    echo "usage: $0 dbname dataname num-cores vmlinux"
    exit 1
fi

labels="runqueues xtime_lock hrtimer_bases rcu_sched_state boot_tvec_bases irq_stack_union blkdev_queue wall_to_monotonic jiffies_64 clocksource_jiffies rcu_sched_state:rcu_node_level_0 timekeeper"

filterlabel=''
for label in $labels; do
    filterlabel="$filterlabel -filter-label $label"
done

filtertidcount='-filter-tid-count 2 -filter-cpu-count 2 -filter-cpu-percent 50'
json='-json True'

./serialsum.py $1 $2 $filterlabel $filtertidcount \
    -exefile $4 -num-cores $3 \
    -print percent -print cpus -print pc -print calls \
    $json
