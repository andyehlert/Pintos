#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include <stddef.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include <list.h>

static void syscall_handler (struct intr_frame *);
static struct lock sys_lock;

void
syscall_init (void) 
{
	lock_init(&sys_lock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Function declarations */
/* Andy driving here */
void halt(void);
void exit(int status);
bool check_args(uint32_t *esp);
bool check_ptr(uint32_t *esp);
tid_t exec(const char *cmd_line);
bool create(const char *file, unsigned initial_size);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);


static void /* switch table that calls methods based on the appropriate system call */
syscall_handler (struct intr_frame *f) 
{
	/* Steve Driving */
	/* Declares a copy of the stack pointer given by the interrupt frame */
	uint32_t *esp_copy = f->esp;
	thread_current()->my_esp = f->esp;

	check_args(esp_copy);

	/* Switch statement based on the given system call number */
	switch(*esp_copy)
	{
		/* Case handles a halt system call */
		case SYS_HALT:
			// printf("%s\n", "Halt system call\n");
			halt();
			break;

		/* Case handles an exit system call */
		case SYS_EXIT:{
			// printf("%s\n", "Exit system call\n");
			uint32_t e_stat = *(uint32_t *) (esp_copy + 1);
			check_args((esp_copy + 1));
			thread_current()->exit_status = e_stat;
			thread_exit();
		}
		break;

		/* Case handles an exec system call */
		case SYS_EXEC:
		 	// printf("%s\n", "Exec system call\n");
			if(check_ptr(esp_copy + 1))
			{
				tid_t result = exec((char *) *(esp_copy + 1));
				f->eax = (uint32_t) result;
			}
			break;

		/* Case handles a wait system call */
		case SYS_WAIT:{
			// printf("%s\n", "Wait system call\n");
			f->eax = (uint32_t) process_wait(*(uint32_t*)f->esp +1);
			break;
		}
			
		/* Case handles a remove system call */
		case SYS_REMOVE:
			// printf("%s\n", "Remove system call\n");
			if(check_ptr(esp_copy + 1))
			{
				tid_t result = filesys_remove((char *) *(esp_copy + 1));
				f->eax = (uint32_t) result;
			}
			break;
			
		/* Case handles an open system call */
		case SYS_OPEN:
			// printf("%s\n", "Open system call\n");
			if(check_ptr(esp_copy + 1))
			{
				char *f_open = (char *) *(esp_copy + 1);
				f->eax = (uint32_t) open(f_open);
			}
			break;
			
		/* Case handles a filesize system call */
		case SYS_FILESIZE:{
			// printf("%s\n", "Size system call\n");
			uint32_t fd = *(uint32_t *) (esp_copy + 1);
			f->eax = (uint32_t) filesize(fd);
			break;
		}
			
		/* Case handles a tell system call */
		case SYS_TELL:{
			// printf("%s\n", "Tell system call\n");
			uint32_t fd = *(uint32_t *) (esp_copy + 1);
			f->eax = (uint32_t) tell(fd);				
			break;
		}
			
		/* Case handles a close system call */
		case SYS_CLOSE:{
			// printf("%s\n", "Close system call\n");
			uint32_t fd = *(uint32_t *) (esp_copy + 1);
			close(fd);			
			break;
		}

		/* Case handles a create system call */
		case SYS_CREATE:
			// printf("%s\n", "Create system call\n");
			if(check_ptr(esp_copy + 1))
			{
				char *f_open = (char *) *(esp_copy + 1);
				uint32_t size = *(uint32_t *) (esp_copy + 2);
				f->eax = (uint32_t) create(f_open, size);
			}
			break;
			
		/* Case handles a seek system call */
		case SYS_SEEK:{
			// printf("%s\n", "Seek system call\n");
			int32_t fd = *(int32_t *) (esp_copy + 1);
			uint32_t position = *(uint32_t *) (esp_copy + 2);
			seek(fd, position);
			break;
		}

		/* Case handles a read system call */
		case SYS_READ:
			// printf("Read system call %s\n", *(esp_copy+2));
			if(check_ptr(esp_copy + 2))
			{
				int32_t fd = *(int32_t *) (esp_copy + 1);
				char *buf = *((uintptr_t *) f->esp + 2);
				uint32_t size = *((uintptr_t *)f->esp + 3);
				f->eax = (uint32_t) read(fd, buf, size);
			}
			break;
			
		/* Case handles a write system call */
		case SYS_WRITE:
			// printf("%s\n", "Write system call\n");
			if(check_ptr(esp_copy + 2))
			{
				uint32_t fd = *((uintptr_t *) f->esp + 1);
				char *buf = *((uintptr_t *) f->esp + 2);
				uint32_t size = *((uintptr_t *)f->esp + 3);
				f->eax = (uint32_t) write(fd, buf, size);
			}
			break;

		default:
			thread_exit();
			break;

	}
}

/* Zach Driving */
/* Function to check the validity of user provided pointers */
bool check_args(uint32_t *esp)
{
	/* Checks to see if user provided pointer is valid, page fault if it is invalid */
	if(!is_user_vaddr(esp))
		my_exit();
	if(esp == NULL)
		my_exit();
	if(pagedir_get_page(thread_current()->pagedir, esp) == NULL)
	{
		my_exit();
	}
	return true;
}

bool check_ptr(uint32_t *esp)
{
	/* Checks to see if user provided pointer is valid, page fault if it is invalid */
	if(!is_user_vaddr(*esp))
		my_exit();
	if(*esp == NULL)
		my_exit();
	if(pagedir_get_page(thread_current()->pagedir, *esp) == NULL)
	{
		my_exit();
	}
	return true;
}


void halt(void) /* shut down */
{
	shutdown_power_off();
}

void exit(int status) /* changes the exit status of the thread */
{
	thread_current()->exit_status = status;
}

//Andy Driving
tid_t exec(const char *cmd_line) /* gives a new program to a process using process_execute */
{
	tid_t result = process_execute(cmd_line);
	if(result == TID_ERROR){
		return -1;
	}
	return result;
}

bool create(const char *file, unsigned initial_size)
{
	if(file == NULL)
		return -1;
	return filesys_create(file, (off_t) initial_size);
}


int open(const char *file) /* opens the specified file */
{
	/* Jerry Driving */
	/* Create struct with file descriptor, file name, and list elem */
	struct file * point = filesys_open(file);
	if(point == NULL)
	{
		return -1;
	}
	else
	{
		int index = 2;
		while(index <=130){
			if(thread_current()->open_files[index] == NULL){
				thread_current()->open_files[index] = point;
				return index;
			}
			index++;
		}
		return -1;
	}
}

int filesize(int fd) /* returns the file size of the file specified by fd */
{
	struct file *file;
	if(fd>130)
		my_exit();
	if(thread_current()->open_files[fd] == NULL)
		{
			return -1;
		}
		else{
			file  = thread_current()->open_files[fd];
			return (uint32_t) file_length(file);
		}
		return -1;
	
}

int read(int fd, void *buffer, unsigned size)
{
	if(fd>130)
		my_exit();
	else if(&buffer == NULL)
		my_exit();
	struct file *file = thread_current()->open_files[fd];
	if(fd == 0)
	{
		input_getc();
		return size;
	}
	else
	{
		if(thread_current()->open_files[fd] == NULL)
		{
			return -1;
		}
		else{
			file  = thread_current()->open_files[fd];
			return (uint32_t) file_read(file, buffer, size);
		}
	}
}


/* if fd = 1 writes to stdout, else writes to the specified file */
int write(int fd, const void *buffer, unsigned size) 
{
	if(fd>130)
		my_exit();
	if(fd == 1)
	{
		putbuf((char *) buffer, size);
		return size;
	}
	else
	{
		struct file *file;
		if(thread_current()->open_files[fd] == NULL)
		{
			return -1;
		}
		else{
			file  = thread_current()->open_files[fd];
			return (uint32_t) file_write(file, buffer, size);
		}
	}
}

void seek(int fd, unsigned position)
{
	if(fd>130){
		my_exit();
	}
	file_seek(thread_current()->open_files[fd], (off_t) position);
}

unsigned tell(int fd)
{
	if(fd>130) {
		my_exit();
	}
	if(thread_current()->open_files[fd]==NULL){
		return -1;
	}
	else{
		uint32_t pos = (uint32_t) file_tell(thread_current()->open_files[fd]);
		return (pos + 1);
	}
}

/* Steve Driving */
void close(int fd) /* closes the specified file */
{
	if(fd>130) {
		my_exit();
	}
	else if(fd == 1) {
		my_exit();
	}
	file_close(thread_current()->open_files[fd]);
	thread_current()->open_files[fd] = NULL;
}

void my_exit() {
	thread_current()-> exit_status = -1;
	thread_exit();
}
