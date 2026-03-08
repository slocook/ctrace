#!/usr/sbin/dtrace -s

/* I/O summary for a target PID */

#pragma D option quiet

syscall::read:entry,
syscall::readv:entry,
syscall::pread:entry
/pid == $target/
{
    self->ts = timestamp;
    self->fd = arg0;
    self->op = "read";
}

syscall::write:entry,
syscall::writev:entry,
syscall::pwrite:entry
/pid == $target/
{
    self->ts = timestamp;
    self->fd = arg0;
    self->op = "write";
}

syscall::read:return,
syscall::readv:return,
syscall::pread:return,
syscall::write:return,
syscall::writev:return,
syscall::pwrite:return
/pid == $target && self->ts/
{
    this->delta = (timestamp - self->ts) / 1000;
    @io_count[self->op, self->fd] = count();
    @io_bytes[self->op, self->fd] = sum(arg1 > 0 ? arg1 : 0);
    @io_latency[self->op, self->fd] = avg(this->delta);
    self->ts = 0;
}
