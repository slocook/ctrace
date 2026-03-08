#!/usr/sbin/dtrace -s

/* Allocation tracing for a target PID */
/* Usage: sudo dtrace -s alloc_trace.d -p <PID> */

#pragma D option quiet

pid$target::malloc:entry
{
    @malloc_count = count();
    @malloc_bytes = sum(arg0);
    @malloc_sizes = quantize(arg0);
}

pid$target::free:entry
{
    @free_count = count();
}

pid$target::realloc:entry
{
    @realloc_count = count();
    @realloc_bytes = sum(arg1);
}
