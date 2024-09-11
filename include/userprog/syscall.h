#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

void syscall_init (void);
void close (int fd);
void error_exit(struct thread *t);

#endif /* userprog/syscall.h */
