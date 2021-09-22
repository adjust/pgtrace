#!/usr/bin/env python3
#
# pglocks.py  Trace lwlock acquiring latency in postgres
#
# Copyright 2021 Adjust GmbH

from __future__ import print_function
from bcc import BPF
from time import strftime, sleep
from lib import pglwl
import sys, threading, argparse, os, re

# arguments
usage = """
    Trace lwlock acquiring latency in postgres
    ./pglocks.py /usr/bin/postgres13
    ./pglocks.py -e -l buffer_mapping,proc,60 -m
    ./pglocky.py -p 26589
"""

parser = argparse.ArgumentParser(
    description="Time postgres LWLock latency",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=usage
)
parser.add_argument("-l", "--lwlocks",
    help="only time a comma separated list of lwlocks"
)
parser.add_argument("-i", "--interval", type=int,
    help="summary intervals in seconds"
)
parser.add_argument("-e", "--events", action="store_true",
    help="print perf_event for every lwlock"
)
parser.add_argument("-p", "--pid", type=int,
    help="pid filter"
)
parser.add_argument("-c", "--count", type=int,
    help="count until exit"
)
parser.add_argument("-s", "--seconds", action="store_true",
    help="display lock acquire times in seconds"
)
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="display lock acquire times in milliseconds"
)
parser.add_argument("-u", "--microseconds", action="store_true",
    help="display lock acquire times in microseconds (default)"
)
parser.add_argument("-n", "--nanoseconds", action="store_true",
    help="display lock acquire times in nanoseconds"
)
parser.add_argument("-r", "--release", action="store_true",
    help="trace lwlock release time"
)
parser.add_argument("-P", "--print-locks", action="store_true",
    help="print list of locks per postgres version"
)
parser.add_argument("postgres", nargs="?",
    help="path to postgres binary"
)

parser.set_defaults(interval=5, postgres="/usr/bin/postgres")
args = parser.parse_args()

# lwlock tranche specific tracing
tranchelist = set()
stream = os.popen(args.postgres + " --version",mode='r')
postgres = stream.read()
rv = stream.close()
if rv:
    print("Couldn't run %s, exit value %d" % (args.postgres, rv >> 8))
    exit(1)
postgres_version = re.search(r'(\d+\.\d+(?:\.\d+)?)$', postgres)
if not postgres_version:
    print("Couldn't determine postgres version: %s" % postgres)
    exit(1)

l = pglwl.Locknames(postgres_version.group(1))

if args.print_locks:
    l.print_locks()
    exit(0)

if args.lwlocks:
    args.lwlocks = args.lwlocks.split(',')
    for lwl in args.lwlocks:
        try:
            int(lwl)
            tranchelist.add(lwl)
        except:
            lwl = l.get_id_by_lockname(lwl)
            if(not lwl):
                exit(1)
            tranchelist.add(str(lwl))

# define BPF program
bpf_text="""
#include <uapi/linux/ptrace.h>

struct str_t {
    u64 pid;
    u64 delta;
    u16 tranche_id;
};

// datastructure ressembling lwlocks from postgres
typedef struct lwlock {
    u16 tranche;
    u32 state;
    void *waiters;
} lwlock_t;

BPF_PERF_OUTPUT(events);
BPF_HASH(timings);
BPF_HISTOGRAM(dist);

BPF_HISTOGRAM(dist_release);
BPF_HASH(timings_release);


int lwlock_enter(struct pt_regs *ctx, lwlock_t *lock) {
    struct str_t data = {};
    u64 ts = bpf_ktime_get_ns();
    u16 tranches[] = { TRANCHEFILTER };

    data.pid = (u64) bpf_get_current_pid_tgid() >> 32;
    data.tranche_id = lock->tranche;
    PIDFILTER

    PRINTEVENTS

    TIMINGFILTER

    return 0;
}

int lwlock_leave(struct pt_regs *ctx, lwlock_t *lock) {
    struct str_t data = {};
    u64 ts = bpf_ktime_get_ns();

    data.pid = (u64) bpf_get_current_pid_tgid() >> 32;
    PIDFILTER

    // find timestamp for local pid
    u64 *tsp;
    tsp = timings.lookup(&data.pid);
    if (!tsp)
        goto exit; // no pid available

    data.delta = ts - *tsp;

    // convert to unit
    data.delta /= SHIFT;

    // increase this distribution map key by one
    dist.increment(bpf_log2l(data.delta));

    // remove pid from hash table
    timings.delete(&data.pid);

    exit:
    return 0;
}

int lwlockrelease_enter(struct pt_regs *ctx, lwlock_t *lock) {
    struct str_t data = {};
    u64 ts = bpf_ktime_get_ns();
    u16 tranches[] = { TRANCHEFILTER };

    data.pid = (u64) bpf_get_current_pid_tgid() >> 32;
    data.tranche_id = lock->tranche;
    PIDFILTER

    PRINTEVENTS

    TIMINGRELEASEFILTER

    return 0;
}

int lwlockrelease_leave(struct pt_regs *ctx, lwlock_t *lock) {
    struct str_t data = {};
    u64 ts = bpf_ktime_get_ns();

    data.pid = (u64) bpf_get_current_pid_tgid() >> 32;
    PIDFILTER

    // find timestamp for local pid
    u64 *tsp;
    tsp = timings.lookup(&data.pid);
    if (!tsp)
        goto exit; // no pid available

    data.delta = ts - *tsp;

    // convert to unit
    data.delta /= SHIFT;

    // increase this distribution map key by one
    dist_release.increment(bpf_log2l(data.delta));

    // remove pid from hash table
    timings_release.delete(&data.pid);

    exit:
    return 0;
}
"""

bpf_text = bpf_text.replace('TRANCHEFILTER', ','.join(tranchelist));


#PID filter
if(args.pid):
    bpf_text = bpf_text.replace('PIDFILTER',
    """
        if (data.pid != %d) {return 0;}
    """ % args.pid
    )
else:
    bpf_text = bpf_text.replace('PIDFILTER','')

# lwlock filter, event printing
if(args.lwlocks):
    if(args.events):
        bpf_text = bpf_text.replace('PRINTEVENTS',
        """
        for(int i = 0; i < sizeof(tranches)/sizeof(u16); i++)
            if(tranches[i] == lock->tranche) {
                events.perf_submit(ctx,&data,sizeof(data));
            }
        """
        )
    else:
        bpf_text = bpf_text.replace('PRINTEVENTS','')

    bpf_text = bpf_text.replace('TIMINGFILTER',
    """
    for(int i = 0; i < sizeof(tranches)/sizeof(u16); i++) {
        if (tranches[i] == lock->tranche ) {
            timings.update(&data.pid, &ts);
            break;
        }
    }
    """
    )
    bpf_text = bpf_text.replace('TIMINGRELEASEFILTER',
    """
    for(int i = 0; i < sizeof(tranches)/sizeof(u16); i++) {
        if (tranches[i] == lock->tranche ) {
            timings.update(&data.pid, &ts);
            break;
        }
    }
    """
    )
else:
    if(args.events):
        bpf_text = bpf_text.replace('PRINTEVENTS',
        """
        events.perf_submit(ctx,&data,sizeof(data));
        """)
    else:
        bpf_text = bpf_text.replace('PRINTEVENTS','')
    bpf_text = bpf_text.replace('TIMINGFILTER',
    """
    timings.update(&data.pid, &ts);
    """
    )
    bpf_text = bpf_text.replace('TIMINGRELEASEFILTER',
    """
    timings.update(&data.pid, &ts);
    """
    )

# time shift
if args.seconds:
    bpf_text = bpf_text.replace('SHIFT', '(1000*1000*1000)')
    shift = "sec"
elif args.milliseconds:
    bpf_text = bpf_text.replace('SHIFT', '(1000*1000)')
    shift = "msec"
elif args.microseconds:
    bpf_text = bpf_text.replace('SHIFT', '1000')
    shift = "usec"
elif args.nanoseconds:
    bpf_text = bpf_text.replace('SHIFT', '1')
    shift = "nsec"
else:
    bpf_text = bpf_text.replace('SHIFT', '1000')
    shift = "usec"

# compile BPF program
b = BPF(text=bpf_text)

# hook functions
b.attach_uprobe(name=args.postgres,
    sym="LWLockAcquire", fn_name="lwlock_enter")
b.attach_uretprobe(name=args.postgres,
    sym="LWLockAcquire", fn_name="lwlock_leave")
if args.release:
    b.attach_uprobe(name=args.postgres,
        sym="LWLockRelease", fn_name="lwlockrelease_enter")
    b.attach_uretprobe(name=args.postgres,
        sym="LWLockRelease", fn_name="lwlockrelease_leave")

print("Attaching to LWLockAcquire %s, Ctrl+C to quit." %
        ( "in pid %d" % args.pid if args.pid else "system wide")
)
if args.lwlocks:
    print("Tracing lwlocks: %s " % ','.join(
        list(map(lambda x: l.get_lockname_by_id(x),tranchelist)))
    )

# event printing needs to be a worker so it can print asynchronously
def event_buffer_worker():
    while 1:
        b.perf_buffer_poll(timeout=1*1000)
        if(exiting == 1):
            exit()

def print_event(cpu,data,size):
    event = b["events"].event(data)

    print("%-9s pid:%d tranche_id:%d tranche_name:%s" % (strftime("%H:%M:%S"),
        event.pid,
        event.tranche_id,
        l.get_lockname_by_id(event.tranche_id)))


exiting = 0
count = 0

b["events"].open_perf_buffer(print_event);
worker = threading.Thread(target=event_buffer_worker)
worker.start()

dist = b.get_table("dist")
dist_release = b.get_table("dist_release")
while 1:
    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exiting = 1

    print("%-9s" % strftime("%H:%M:%S"))
    print("LWLocks acquired")
    dist.print_log2_hist(shift, "lwlock_enter")
    dist.clear()

    if args.release:
        print("LWLocks released")
        dist_release.print_log2_hist(shift, "lwlockrelease_enter")
        dist_release.clear()

    count += 1
    if count == args.count:
        exiting = 1

    if exiting:
        worker.join()
        exit()
