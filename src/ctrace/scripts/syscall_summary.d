#!/usr/sbin/dtrace -s

/* Syscall summary: count and latency per syscall for a target PID */
/* Usage: sudo dtrace -s syscall_summary.d -p <PID> */

#pragma D option quiet

syscall:::entry
/pid == $target/
{
    self->ts = timestamp;
    @counts[probefunc] = count();
}

syscall:::return
/pid == $target && self->ts/
{
    this->delta = (timestamp - self->ts) / 1000;
    @latency[probefunc] = sum(this->delta);
    @dist[probefunc] = quantize(this->delta);
    self->ts = 0;
}
