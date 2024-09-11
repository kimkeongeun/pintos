#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

//추가
#include "filesys/filesys.h"
#include "lib/string.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/palloc.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

unsigned tell (int fd);
int write (int fd, void *buffer, unsigned size);
int create (const char *file, unsigned initial_size);
int file_size (int fd);
int read_page (int fd, void *buffer, unsigned size);
int remove (const char *file);
void seek (int fd, unsigned position);
void page_check(struct thread *t, struct intr_frame *f, uint64_t *r);
tid_t fork (const char *thread_name, struct intr_frame *f);
int wait(int pid);
int exec(const char *cmd_line);

struct lock filesys_lock;
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	struct thread *curr = thread_current ();

	switch(f->R.rax){
		case SYS_HALT:
			power_off();
			break;
		case SYS_EXIT:
			f->R.rax = f->R.rdi;
			curr->exit = 1;
			curr->exit_code = f->R.rdi;
			thread_exit();
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_CREATE:
			page_check(curr, f, f->R.rdi);
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_OPEN:
			page_check(curr, f, f->R.rdi);
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = file_size (f->R.rdi);
			break;
		case SYS_READ:
			page_check(curr, f, f->R.rsi);
			f->R.rax = read_page(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			page_check(curr, f, f->R.rsi);
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx); 
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
	}

}

void error_exit(struct thread *t){
	t->exit = 1;
	t->exit_code = -1;
	thread_exit();
}


int
create (const char *file, unsigned initial_size) {
	if(file!=NULL){
		if(filesys_create(file, initial_size)){
			return 1;
		}
	}
	return 0;
}

int 
write (int fd, void *buffer, unsigned size){
	struct thread *curr = thread_current ();
	
	if(fd == 1 && buffer!=NULL){
		putbuf(buffer, size);
		return size;
	}else if(fd>2 && fd<10 && buffer!=NULL){
		if(curr->fd_list[fd]){
			lock_acquire(&filesys_lock);
			//읽고 반환.
			int a = file_write(curr->fd_list[fd], buffer, size);
			lock_release(&filesys_lock);
			return a;	
		}
	}else{
		return -1;
	}
}


int
open (const char *file) {
	struct thread *curr = thread_current ();

	if(file==NULL)
		return -1;

	struct file *f = filesys_open (file);
	if(f==NULL)
		return -1;
	
	for(int i=3;i<10;i++){
		if(curr->fd_list[i] == NULL){
			if (!strcmp(thread_name(), file))
				file_deny_write(f);
			curr->fd_list[i] = f;
			return i;
		}
	}


	return -1;
}

int remove (const char *file){
	if(file==NULL)
		return 0;
	return filesys_remove(file);
};

int wait(int pid)
{
    return process_wait(pid);
}

void page_check(struct thread *t, struct intr_frame *f, uint64_t *r){
	if(r>(uint64_t)USER_STACK){
		f->R.rax = -1;
		error_exit(t);
	}
	
	if(pml4_get_page (t->pml4, r) == NULL){
		f->R.rax = -1;
		error_exit(t);				
	}
}

int read_page (int fd, void *buffer, unsigned size){
	struct thread *curr = thread_current ();


	if(fd==0 && buffer!=NULL){
		input_getc();
		return size;
	}else if(fd>2 && fd<10 && buffer!=NULL){
		//fd 테이블에서 페이지 포인터를 넘김
		
		if(curr->fd_list[fd]){
			lock_acquire(&filesys_lock);
			int a = file_read(curr->fd_list[fd], buffer, size);		
			lock_release(&filesys_lock);
			return a;	
		}
	}

	return -1;
}


int file_size (int fd){
	struct thread *curr = thread_current ();
	if(fd>2 && fd<10){
		return file_length(curr->fd_list[fd]);
	}
	return -1;
};

void close (int fd) {
	struct thread *curr = thread_current ();
	if(fd>2 && fd<10){
		file_close(curr->fd_list[fd]);
		curr->fd_list[fd]=NULL;
	}
}

unsigned tell (int fd) {
	struct thread *curr = thread_current ();
	if(fd>2 && fd<10 && curr->fd_list[fd]){
		return file_tell(curr->fd_list[fd]);
	}
	return -1;
}

void seek (int fd, unsigned position){
	struct thread *curr = thread_current ();
	if(fd>2 && fd<10 && curr->fd_list[fd] && position>= 0){
		return file_seek(curr->fd_list[fd], position);
	}
	return -1;
}

//pid_t 타입은 정의 x. 그냥 tid_t 사용.
tid_t fork (const char *thread_name, struct intr_frame *f){
	return process_fork(thread_name, f);
}


int exec(const char *cmd_line)
{
    // process.c 파일의 process_create_initd 함수와 유사하다.
    // 단, 스레드를 새로 생성하는 건 fork에서 수행하므로
    // 이 함수에서는 새 스레드를 생성하지 않고 process_exec을 호출한다.

    // process_exec 함수 안에서 filename을 변경해야 하므로
    // 커널 메모리 공간에 cmd_line의 복사본을 만든다.
    // (현재는 const char* 형식이기 때문에 수정할 수 없다.)
    char *cmd_line_copy;
    cmd_line_copy = palloc_get_page(0);
    if (cmd_line_copy == NULL)
        error_exit(thread_current ());    // 메모리 할당 실패 시 status -1로 종료한다.
    strlcpy(cmd_line_copy, cmd_line, PGSIZE); // cmd_line을 복사한다.

    // 스레드의 이름을 변경하지 않고 바로 실행한다.
    if (process_exec(cmd_line_copy) == -1)
        error_exit(thread_current ()); // 실패 시 status -1로 종료한다.
}