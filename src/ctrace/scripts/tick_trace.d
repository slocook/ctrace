#!/usr/sbin/dtrace -s

/* Tick/frame tracing template for a target PID */
/* Replace TICK_FUNC with the actual function name */

#pragma D option quiet

pid$target::TICK_FUNC:entry
{
    self->tick_start = timestamp;
    self->tick_syscalls = 0;
    self->tick_allocs = 0;
}

syscall:::entry
/pid == $target && self->tick_start/
{
    self->tick_syscalls++;
}

pid$target::malloc:entry
/self->tick_start/
{
    self->tick_allocs++;
}

pid$target::TICK_FUNC:return
/self->tick_start/
{
    this->dur = (timestamp - self->tick_start) / 1000;
    printf("TICK|%d|%d|%d\n", this->dur, self->tick_syscalls, self->tick_allocs);
    @durations = quantize(this->dur);
    self->tick_start = 0;
}
