/*
 *  linux/kernel/fork.c
 *
 *  (C) 1991  Linus Torvalds
 */

/*
 *  'fork.c' contains the help-routines for the 'fork' system call
 * (see also system_call.s), and some misc functions ('verify_area').
 * Fork is rather simple, once you get the hang of it, but the memory
 * management can be a bitch. See 'mm/mm.c': 'copy_page_tables()'
 */
#include <errno.h>

#include <linux/sched.h>
#include <linux/kernel.h>
#include <asm/segment.h>
#include <asm/system.h>

extern void write_verify(unsigned long address);

long last_pid=0;

void verify_area(void * addr,int size)
{
	unsigned long start;

	start = (unsigned long) addr;
	size += start & 0xfff;
	start &= 0xfffff000;
	start += get_base(current->ldt[2]);
	while (size>0) {
		size -= 4096;
		write_verify(start);
		start += 4096;
	}
}

int copy_mem(int nr,struct task_struct * p)
{
	unsigned long old_data_base,new_data_base,data_limit;
	unsigned long old_code_base,new_code_base,code_limit;
    /**
     * 取子进程的 code、data 长度limit
     * 0x0f:  1111 -> code段、LDT、特权级3
     * 0x17: 10111 -> data段、LDT、特权级3
     */
	code_limit=get_limit(0x0f);
	data_limit=get_limit(0x17);
    // 获取父进程的 code 和 data 的base
	old_code_base = get_base(current->ldt[1]);
	old_data_base = get_base(current->ldt[2]);
	if (old_data_base != old_code_base)
		panic("We don't support separate I&D");
	if (data_limit < code_limit)
		panic("Bad data_limit");
    /**
     * TASK_SIZE = 64MB，在Linux0.11、0.12版本中，每一个进程的空间为64MB
     * 这一版本的Linux最多支持64个进程，也就是64*64MB = 4GB（正好是X86 32位CPU可以寻址的上限）
     * 使用 set_base 这个宏，将code、data的base，加上特权级以及段信息等，形成一个段描述符（segment describe）
     */
	new_data_base = new_code_base = nr * TASK_SIZE;
	p->start_code = new_code_base;
	set_base(p->ldt[1],new_code_base);
	set_base(p->ldt[2],new_data_base);
	if (copy_page_tables(old_data_base,new_data_base,data_limit)) {
		free_page_tables(new_data_base,data_limit);
		return -ENOMEM;
	}
	return 0;
}

/*
 *  Ok, this is the main fork-routine. It copies the system process
 * information (task[nr]) and sets up the necessary registers. It
 * also copies the data segment in it's entirety.
 */
int copy_process(int nr,long ebp,long edi,long esi,long gs,long none,
		long ebx,long ecx,long edx, long orig_eax, 
		long fs,long es,long ds,
		long eip,long cs,long eflags,long esp,long ss)
{
	struct task_struct *p;
	int i;
	struct file *f;

	/**
	 * get_free_page其实申请的是一个 task_union 结构，正好是一个页大小（4KB)**/
	p = (struct task_struct *) get_free_page();
	if (!p)
		return -EAGAIN;
	task[nr] = p;
	*p = *current;	/* NOTE! this doesn't copy the supervisor stack */
	p->state = TASK_UNINTERRUPTIBLE;
	p->pid = last_pid;
	p->counter = p->priority;
	p->signal = 0;
	p->alarm = 0;
	p->leader = 0;		/* process leadership doesn't inherit */
	p->utime = p->stime = 0;
	p->cutime = p->cstime = 0;
	p->start_time = jiffies;
	
	/**
	tss 参考下文中的描述，利用了CPU的规则，用于保留进程的上下文
	*/
	p->tss.back_link = 0;
	p->tss.esp0 = PAGE_SIZE + (long) p; // !!!!!esp0 是进程的内核stack基址（stack从高地址向低地址生长），因为task_union申请了一个PAGE_SIZE(4KB)，所以，内核stack的基址就是这个task_union的页面最高位，也就是 p(开始的地址）+ PAGE_SIZE!!!!!!!!!!
	p->tss.ss0 = 0x10; // 0x10 == 10000, DPL = 0, GDT, 数据段
	p->tss.eip = eip;
	p->tss.eflags = eflags;
	p->tss.eax = 0; // !!!!!!!这里的这个操作，就是保障fork()在子进程中，返回0 的原理!!!!!!!!
	p->tss.ecx = ecx;
	p->tss.edx = edx;
	p->tss.ebx = ebx;
	p->tss.esp = esp;
	p->tss.ebp = ebp;
	p->tss.esi = esi;
	p->tss.edi = edi;
	p->tss.es = es & 0xffff;
	p->tss.cs = cs & 0xffff;
	p->tss.ss = ss & 0xffff;
	p->tss.ds = ds & 0xffff;
	p->tss.fs = fs & 0xffff;
	p->tss.gs = gs & 0xffff;
	p->tss.ldt = _LDT(nr);
	p->tss.trace_bitmap = 0x80000000;
	/** End of TSS*/

	if (last_task_used_math == current)
		__asm__("clts ; fnsave %0 ; frstor %0"::"m" (p->tss.i387));
	if (copy_mem(nr,p)) {
		task[nr] = NULL;
		free_page((long) p);
		return -EAGAIN;
	}
	for (i=0; i<NR_OPEN;i++)
		if (f=p->filp[i])
			f->f_count++;
	if (current->pwd)
		current->pwd->i_count++;
	if (current->root)
		current->root->i_count++;
	if (current->executable)
		current->executable->i_count++;
	if (current->library)
		current->library->i_count++;
	/** 设置TSS是线程切换的关键，Linux复用了CPU提供的上下文切换的机制 
	1. 定义了struct TSS，符合CPU关于TSS定义的内存位置
	2. 这里关联struct的TSS内存区域到GDT中（生成TSS内存区域对应的段描述符，添加到GDT中）
	3. 线程切换时候，在CPL=0（线程切换仅由CPU的时钟中断，执行do_timer时候调用 schedule 函数），这时线程是用户线程，但是因为是时钟中断引起的操作，所以是在CPL=0的内核态。
	这个时候，使用LJMP跳转到其他线程，是可以的（CPL == 0, DPL == 3, RPL == 0）
	在LJMP执行过程中，
	1. CPU会将所有上下文相关的寄存器内存，储存到TR寄存器，然后，赋值给TSS段描述符对应的内存区域，完成对原有进程上下文的保存
	2. 同时，加载段选择子对应的段描述符（新进程的TSS），解析出TSS中的LDT、堆栈寄存器等，跳转到新的进程对应的代码(CS:IP)处，继续执行代码逻辑
	*/
	set_tss_desc(gdt+(nr<<1)+FIRST_TSS_ENTRY,&(p->tss));
	set_ldt_desc(gdt+(nr<<1)+FIRST_LDT_ENTRY,&(p->ldt));
	p->p_pptr = current;
	p->p_cptr = 0;
	p->p_ysptr = 0;
	p->p_osptr = current->p_cptr;
	if (p->p_osptr)
		p->p_osptr->p_ysptr = p;
	current->p_cptr = p;
	p->state = TASK_RUNNING;	/* do this last, just in case */
	return last_pid;
}

int find_empty_process(void)
{
	int i;

	repeat:
		if ((++last_pid)<0) last_pid=1;
		for(i=0 ; i<NR_TASKS ; i++)
			if (task[i] && ((task[i]->pid == last_pid) ||
				        (task[i]->pgrp == last_pid)))
				goto repeat;
	for(i=1 ; i<NR_TASKS ; i++)
		if (!task[i])
			return i;
	return -EAGAIN;
}
