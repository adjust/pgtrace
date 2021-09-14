#!/bin/bash
# pglwlockcount.sh
# trace num_held_lwlocks per time interval
# degrades performance as it stops process
#
# Copyright 2021 Adjust GmbH

usage() {
	cat << EOF 1>&2
Usage: $0 [-t <interval> ] [ -s ] -p <pid>
	-t interval in seconds
	-s statistics per tranche id
	-p pid of postgres process
EOF
exit 1;
}

LOCKSTATS='return;'
INTERVAL=1

while getopts "s :tp:" o
do
	case "${o}" in
		t)
			INTERVAL=${OPTARG}
			echo $INTERVAL | grep -Eq '^[1-9][0-9]*s?$' || usage
		;;
		p)
			PID=${OPTARG}
			echo $PID | grep -Eq '^[1-9][0-9]*$' || usage
		;;
		s)
			LOCKSTATS=''
		;;
		*)
			usage
		;;
	esac
done

[ -z $PID ] && usage


# BPFTRACE can not resolve the address of global variables for a watchpoint
echo "Trying to resolve num_held_lwlocks"
NUMLWLOCKS=$(echo "p &num_held_lwlocks" |\
	gdb -p $PID 2>/dev/null |\
	gawk 'match($0,/(0x[a-f0-9]+)[[:space:]]+<num_held_lwlocks>/,a) {print a[1]}'
)

echo "Trying to resolve held_lwlocks"
LWLOCKS=$(echo "p &held_lwlocks" |\
	gdb -p $PID 2>/dev/null |\
	gawk 'match($0,/(0x[a-f0-9]+)[[:space:]]+<held_lwlocks>/,a) {print a[1]}'
)

[ -z $NUMLWLOCKS ] && echo "Could not resolve symbol num_held_lwlocks!" 1>&2 && exit 1

echo "Got $NUMLWLOCKS $LWLOCKS"
bpftrace -e "

// pseudo data structures from postgres, may change
struct LWLock { u16 tranche; u32 state; };

struct LWLockHandle { struct LWLock *lock; void *mode};

// We only care about writes (reads don't alter the value)

watchpoint:${NUMLWLOCKS}:4:w
{
	@max = max((int32) *${NUMLWLOCKS});

	// We only want to know when a lock is acquired
	if (@last <= (int32) *${NUMLWLOCKS})
	{
		@count = count();
	}
	@last = (int32) *${NUMLWLOCKS};

	// We need a variable that can act as a boolean
	// so we can print only if there is an event
	@new = 1;


	// Skip this block conditionally on user input
	$LOCKSTATS
	\$i = 0;
	while (\$i < (int32) *${NUMLWLOCKS}) {
		\$lock = (struct LWLockHandle *)
			(${LWLOCKS}+ (\$i* (int32) sizeof(struct LWLockHandle)));
		\$tranche = (\$lock)->lock->tranche;

		\$i++;
		if (\$i >= 1024) { break; }
		// TrancheID 0 is available
		if (\$tranche == 0) { continue; }

		@locks[\$tranche]++;
		if (@lockstats[\$tranche] < @locks[\$tranche]) {
			@lockstats[\$tranche] = @locks[\$tranche];
		}
	}

	// zeroing maps doesn't work synchronously
	\$i = 0;
	while (\$i < 128 )
	{
		delete(@locks[\$i]);
		\$i++;
	}
}
interval:s:${INTERVAL}
{
	if(@new == 1) {
		time(\"%H:%M:%S lock_max&lock_count/${INTERVAL}s:\\n\");
		print(@max);
		print(@count);
		clear(@max);
		clear(@count);
		clear(@last);
		@new = 0;
		$LOCKSTATS
		print(@lockstats);
		clear(@lockstats);
	}
}
	" -p $PID
