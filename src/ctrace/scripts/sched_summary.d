#!/usr/sbin/dtrace -s

/* Scheduling summary for a target PID */

#pragma D option quiet

sched:::off-cpu
/pid == $target/
{
    self->off_ts = timestamp;
    @ctx_switches[tid] = count();
}

sched:::on-cpu
/pid == $target && self->off_ts/
{
    this->off_time = (timestamp - self->off_ts) / 1000;
    @off_cpu_us[tid] = sum(this->off_time);
    @wakeup_latency[tid] = avg(this->off_time);
    self->off_ts = 0;
}

sched:::on-cpu
/pid == $target/
{
    self->on_ts = timestamp;
}

sched:::off-cpu
/pid == $target && self->on_ts/
{
    @on_cpu_us[tid] = sum((timestamp - self->on_ts) / 1000);
    self->on_ts = 0;
}
