#!/bin/bash
# pglwlockcount.sh
# trace num_held_lwlocks per time interval
# degrades performance as it stops process

usage() { echo "Usage: $0 [-t <interval> ] -p <pid> " 1>&2; exit 1; }


while getopts ":t:p:" o
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
		*)
			usage
		;;
	esac
done

[ -z $PID ] && usage


# BPFTRACE can not resolve the address of global variables for a watchpoint
echo "Trying to resolve num_held_lwlocks"
ADDR=$(echo "p &num_held_lwlocks" |\
	gdb -p $PID 2>/dev/null |\
	gawk 'match($0,/(0x[a-f0-9]+)[[:space:]]+<num_held_lwlocks>/,a) {print a[1]}'
)

[ -z $ADDR ] && echo "Could not resolve symbol num_held_lwlocks!" 1>&2 && exit 1

echo "Got $ADDR"

bpftrace -e "
// We only care about writes (reads don't alter the value)
watchpoint:${ADDR}:4:w 
{
	@max = max((int32) *${ADDR});

	// We only want to know when a lock is acquired
	if (@last <= (int32) *${ADDR}) 
	{
		@count = count();
	}
	@last = (int32) *${ADDR};

	// We need avariable that can act as a boolean
	// so we can print only if there is an event
	@new = 1;
}
interval:s:${INTERVAL}
{
	
	if(@new == 1) {
		time(\"%H:%M:%S lock_max-lock_count/${INTERVAL}s:\\n\");
		print(@max);
		print(@count);
		clear(@max);
		clear(@count);
		clear(@last);
		@new = 0;
	}
}
	" -p $PID
