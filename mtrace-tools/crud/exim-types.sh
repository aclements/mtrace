#!/bin/sh

set -e

if [ $# -ne "2" ]; then
    echo "usage: $0 exim-type divisor"
    exit 1
fi

name=$1
div=$2

labels="xtime xtime_lock jiffies_64 clocksource_jiffies hrtimer_bases boot_tvec_bases rcu_sched_state timekeeper rcu_bh_data"
filterlabel=''
for label in $labels; do
    filterlabel="$filterlabel -filterlabel $label"
done

./summary.py exim-$name.db smtpbm $filterlabel -summarize types -divisor $2 > type-exim-$name.out
cat type-exim-$name.out
