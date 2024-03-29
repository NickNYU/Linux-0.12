/*
 *  linux/mm/memory.c
 *
 *  (C) 1991  Linus Torvalds
 */

/*
 * demand-loading started 01.12.91 - seems it is high on the list of
 * things wanted, and it should be easy to implement. - Linus
 */

/*
 * Ok, demand-loading was easy, shared pages a little bit tricker. Shared
 * pages started 02.12.91, seems to work. - Linus.
 *
 * Tested sharing by executing about 30 /bin/sh: under the old kernel it
 * would have taken more than the 6M I have free, but it worked well as
 * far as I could see.
 *
 * Also corrected some "invalidate()"s - I wasn't doing enough of them.
 */

/*
 * Real VM (paging to/from disk) started 18.12.91. Much more work and
 * thought has to go into this. Oh, well..
 * 19.12.91  -  works, somewhat. Sometimes I get faults, don't know why.
 *		Found it. Everything seems to work now.
 * 20.12.91  -  Ok, making the swap-device changeable like the root.
 */

#include <signal.h>

//#include <asm/system.h>

//#include <linux/sched.h>
//#include <linux/head.h>
//#include <linux/kernel.h>
#include "../include/linux/mm.h"
#include "../include/linux/sched.h"
#include "../include/linux/head.h"
#include "../include/linux/kernel.h"

#include "../include/asm/system.h"

#define CODE_SPACE(addr) ((((addr)+4095)&~4095) < \
current->start_code + current->end_code)

unsigned long HIGH_MEMORY = 0;

/**
 * 这段代码是一个宏定义，用于在汇编语言中实现页面拷贝操作。让我们逐行解释：

1. `#define copy_page(from,to)`：
   - 这是一个宏定义，将 `copy_page(from, to)` 定义为后面的一系列代码。

2. `__asm__("cld ; rep ; movsl"`：
   - 这是一个内嵌的汇编代码块，使用了GCC的`__asm__`扩展。内嵌汇编允许在C代码中嵌入汇编指令。
   - `cld` 指令是“清方向标志”指令，它将方向标志位 (`DF`) 设置为向前移动。
   - `rep` 前缀是“重复”前缀，它指示CPU重复执行接下来的指令，直到`CX`计数器减为零。
   - `movsl` 是“串传送”指令，它将 `DS:SI` 指向的数据块复制到 `ES:DI` 指向的地址，并且 `SI` 和 `DI` 寄存器自动增加。

3. `::"S" (from),"D" (to),"c" (1024)`：
   - 这是输入操作数列表，用于将C语言变量映射到汇编语言的寄存器或内存位置。
   - `"S" (from)` 将C变量 `from` 映射到 `SI` 寄存器，作为源地址。
   - `"D" (to)` 将C变量 `to` 映射到 `DI` 寄存器，作为目标地址。
   - `"c" (1024)` 将常数 `1024` 映射到 `CX` 寄存器，作为数据块的大小。

4. `:"cx","di","si"`：
   - 这是一个输出操作数列表，用于告诉编译器哪些寄存器会被修改。
   - `CX`，`DI` 和 `SI` 寄存器在`movsl`指令执行过程中被修改。

这段代码的作用是将地址 `from` 指向的数据块拷贝到地址 `to` 指向的位置，总共拷贝1024个字（或32位）数据。
 */
#define copy_page(from,to) \
__asm__("cld ; rep ; movsl"::"S" (from),"D" (to),"c" (1024):"cx","di","si")

unsigned char mem_map [ PAGING_PAGES ] = {0,};

/*
 * Free a page of memory at physical address 'addr'. Used by
 * 'free_page_tables()'
 */
void free_page(unsigned long addr)
{
	if (addr < LOW_MEM) return;
	if (addr >= HIGH_MEMORY)
		panic("trying to free nonexistent page");
	addr -= LOW_MEM;
	addr >>= 12;
	if (mem_map[addr]--) return;
	mem_map[addr]=0;
	panic("trying to free free page");
}

/*
 * This function frees a continuos block of page tables, as needed
 * by 'exit()'. As does copy_page_tables(), this handles only 4Mb blocks.
 */
int free_page_tables(unsigned long from,unsigned long size)
{
	unsigned long *from_page_table;
	unsigned long * from_dir, nr;

	if (from & 0x3fffff)
		panic("free_page_tables called with wrong alignment");
	if (!from)
		panic("Trying to free up swapper memory space");
	size = (size + 0x3fffff) >> 22;                 /** >> 22是4 MB数 */
    from_dir = (unsigned long *) ((from>>20) & 0xffc); /* _pg_dir = 0 */

	for ( ; size-->0 ; from_dir++) {
		if (!(1 & *from_dir))
			continue;
        /**from_dir是页目录项中的地址，0xfffff000&是将低12位清零，高20位是页表的地址*/
        from_page_table = (unsigned long *) (0xfffff000 & *from_dir);
		for (nr=0 ; nr<1024 ; nr++) {
			if (*from_page_table) {
				if (1 & *from_page_table)
					free_page(0xfffff000 & *from_page_table);
				else
					swap_free(*from_page_table >> 1);
				*from_page_table = 0;
			}
            from_page_table++;
		}
		free_page(0xfffff000 & *from_dir);
		*from_dir = 0;
	}
	invalidate();
	return 0;
}

/*
 *  Well, here is one of the most complicated functions in mm. It
 * copies a range of linerar addresses by copying only the pages.
 * Let's hope this is bug-free, 'cause this one I don't want to debug :-)
 *
 * Note! We don't copy just any chunks of memory - addresses have to
 * be divisible by 4Mb (one page-directory entry), as this makes the
 * function easier. It's used only by fork anyway.
 *
 * NOTE 2!! When from==0 we are copying kernel space for the first
 * fork(). Then we DONT want to copy a full page-directory entry, as
 * that would lead to some serious memory waste - we just copy the
 * first 160 pages - 640kB. Even that is more than we need, but it
 * doesn't take any more memory - we don't copy-on-write in the low
 * 1 Mb-range, so the pages can be shared with the kernel. Thus the
 * special case for nr=xxxx.
 */
int copy_page_tables(unsigned long from,unsigned long to,long size)
{
	unsigned long * from_page_table;
	unsigned long * to_page_table;
	unsigned long this_page;
	unsigned long * from_dir, * to_dir;
	unsigned long new_page;
	unsigned long nr;

	if ((from&0x3fffff) || (to&0x3fffff))
		panic("copy_page_tables called with wrong alignment");
    /** 一个页目录项的管理范围是4 MB，一项是4字节，目录项的地址就是项数×4 (对应下文中的 &0xffc)
     * 比如：0项的地址是0，管理范围是0～4 MB，
     * 1项的地址是4，管理范围是4～8 MB，
     * 2项的地址是8，管理范围是8～12MB……
     * (from>>20) & 0xffc) == 相当于 (from >>20) * 4, 页目录项的地址
     * 1. >>20就是地址的MB数，（10，10，12，所以，>>20就是取前12位）
     * 2. 0xffc就是&111111111100，就是4 MB以下部分清零的地址的MB数，也就是页目录项的地址*/
	from_dir = (unsigned long *) ((from>>20) & 0xffc); /* _pg_dir = 0 */
	to_dir = (unsigned long *) ((to>>20) & 0xffc);
    /**
     * size 是原有传进来的to地址的段limit，这里的意思是limit的长度，向上取整（按照页目录数目取整）
     * 0x3fffff 是低23位都是1，也就是，如果size直接 size>>22, 会丢失掉不满一个页目录，所以，要加上一个页目录的大小
     * 核心的逻辑如下：
     * for( ; size-->0 ; from_dir++,to_dir++) {
     *      from_page_table = (unsigned long *) (0xfffff000 & *from_dir);
		    if (!(to_page_table = (unsigned long *) get_free_page()))
			    return -1;
			// 这句是赋值page directory
			*to_dir = ((unsigned long) to_page_table) | 7;
     *      nr = (from==0)?0xA0:1024;
		    for ( ; nr-- > 0 ; from_page_table++,to_page_table++) {
		        this_page = *from_page_table;
		        this_page &= ~2;
			    *to_page_table = this_page;
			}
     * }
     * */
	size = ((unsigned) (size+0x3fffff)) >> 22;
	for( ; size-->0 ; from_dir++,to_dir++) {
        // 最后一位是Present位，如果存在就有问题
		if (1 & *to_dir)
			panic("copy_page_tables: already exist");
		if (!(1 & *from_dir))
			continue;
        // 这里取出的是 高20位（0xfffff000）
		from_page_table = (unsigned long *) (0xfffff000 & *from_dir);
		if (!(to_page_table = (unsigned long *) get_free_page()))
			return -1;	/* Out of memory, see freeing */
        /**
         * 复制 page directory
         * 7 : 111， 代表了 用户进程/读写权限/存在（u/s, r/w, present)
         * 如果from是0的话，代表此时正在内核初始化的过程中（将0号进程复制出1号进程，不需要那么多的内存空间）
         * read_swap_page(this_page>>1, (char *) new_page); 负责将交换空间（swap区）的内容读取到对应的page上
         */
		*to_dir = ((unsigned long) to_page_table) | 7;
		nr = (from==0)?0xA0:1024;
		for ( ; nr-- > 0 ; from_page_table++,to_page_table++) {
			this_page = *from_page_table;
			if (!this_page)
				continue;
            // 这里就是标识 present == 0（不存在），即需要调用swap
			if (!(1 & this_page)) {
				if (!(new_page = get_free_page()))
					return -1;
				read_swap_page(this_page>>1, (char *) new_page);
				*to_page_table = this_page;
				*from_page_table = new_page | (PAGE_DIRTY | 7);
				continue;
			}
            /**
             * 重置页属性，2 是 010， ~2 是 101
             * 代表了 用户、只读、存在（这里设置原页面为只读，不管父子进程，哪个发生在发生写操作时，就会触发page_fault，进行CoW的进程）
             * ，Redis RDB 的原理
             */
			this_page &= ~2;
			*to_page_table = this_page;
			if (this_page > LOW_MEM) {
				*from_page_table = this_page;
				this_page -= LOW_MEM;
				this_page >>= 12;
				mem_map[this_page]++;
			}
		}
	}
    /**
     * #define invalidate() \
__asm__("movl %%eax,%%cr3"::"a" (0))
     将CR3刷新为0，CR3是页表缓存
     */
	invalidate();
	return 0;
}

/*
 * This function puts a page in memory at the wanted address.
 * It returns the physical address of the page gotten, 0 if
 * out of memory (either when trying to access page-table or
 * page.)
 */
static unsigned long put_page(unsigned long page,unsigned long address)
{
	unsigned long tmp, *page_table;

/* NOTE !!! This uses the fact that _pg_dir=0 */

	if (page < LOW_MEM || page >= HIGH_MEMORY)
		printk("Trying to put page %p at %p\n",page,address);
	if (mem_map[(page-LOW_MEM)>>12] != 1)
		printk("mem_map disagrees with %p at %p\n",page,address);
	page_table = (unsigned long *) ((address>>20) & 0xffc);
	if ((*page_table)&1)
		page_table = (unsigned long *) (0xfffff000 & *page_table);
	else {
		if (!(tmp=get_free_page()))
			return 0;
		*page_table = tmp | 7;
		page_table = (unsigned long *) tmp;
	}
	page_table[(address>>12) & 0x3ff] = page | 7;
/* no need for invalidate */
	return page;
}

/*
 * The previous function doesn't work very well if you also want to mark
 * the page dirty: exec.c wants this, as it has earlier changed the page,
 * and we want the dirty-status to be correct (for VM). Thus the same
 * routine, but this time we mark it dirty too.
 */
unsigned long put_dirty_page(unsigned long page, unsigned long address)
{
	unsigned long tmp, *page_table;

/* NOTE !!! This uses the fact that _pg_dir=0 */

	if (page < LOW_MEM || page >= HIGH_MEMORY)
		printk("Trying to put page %p at %p\n",page,address);
	if (mem_map[(page-LOW_MEM)>>12] != 1)
		printk("mem_map disagrees with %p at %p\n",page,address);
	page_table = (unsigned long *) ((address>>20) & 0xffc);
	if ((*page_table)&1)
		page_table = (unsigned long *) (0xfffff000 & *page_table);
	else {
		if (!(tmp=get_free_page()))
			return 0;
		*page_table = tmp|7;
		page_table = (unsigned long *) tmp;
	}
	page_table[(address>>12) & 0x3ff] = page | (PAGE_DIRTY | 7);
/* no need for invalidate */
	return page;
}

void un_wp_page(unsigned long * table_entry)
{
	unsigned long old_page,new_page;

	old_page = 0xfffff000 & *table_entry;
	if (old_page >= LOW_MEM && mem_map[MAP_NR(old_page)]==1) {
		*table_entry |= 2;
		invalidate();
		return;
	}
	if (!(new_page=get_free_page()))
		oom();
	if (old_page >= LOW_MEM)
		mem_map[MAP_NR(old_page)]--;
	copy_page(old_page,new_page);
	*table_entry = new_page | 7;
	invalidate();
}	

/*
 * This routine handles present pages, when users try to write
 * to a shared page. It is done by copying the page to a new address
 * and decrementing the shared-page counter for the old page.
 *
 * If it's in code space we exit with a segment error.
 */
void do_wp_page(unsigned long error_code,unsigned long address)
{
	if (address < TASK_SIZE)
		printk("\n\rBAD! KERNEL MEMORY WP-ERR!\n\r");
	if (address - current->start_code > TASK_SIZE) {
		printk("Bad things happen: page error in do_wp_page\n\r");
		do_exit(SIGSEGV);
	}
#if 0
/* we cannot do this yet: the estdio library writes to code space */
/* stupid, stupid. I really want the libc.a from GNU */
	if (CODE_SPACE(address))
		do_exit(SIGSEGV);
#endif
	un_wp_page((unsigned long *)
		(((address>>10) & 0xffc) + (0xfffff000 &
		*((unsigned long *) ((address>>20) &0xffc)))));

}

void write_verify(unsigned long address)
{
	unsigned long page;

	if (!( (page = *((unsigned long *) ((address>>20) & 0xffc)) )&1))
		return;
	page &= 0xfffff000;
	page += ((address>>10) & 0xffc);
	if ((3 & *(unsigned long *) page) == 1)  /* non-writeable, present */
		un_wp_page((unsigned long *) page);
	return;
}

void get_empty_page(unsigned long address)
{
	unsigned long tmp;

	if (!(tmp=get_free_page()) || !put_page(tmp,address)) {
		free_page(tmp);		/* 0 is ok - ignored */
		oom();
	}
}

/*
 * try_to_share() checks the page at address "address" in the task "p",
 * to see if it exists, and if it is clean. If so, share it with the current
 * task.
 *
 * NOTE! This assumes we have checked that p != current, and that they
 * share the same executable or library.
 */
static int try_to_share(unsigned long address, struct task_struct * p)
{
	unsigned long from;
	unsigned long to;
	unsigned long from_page;
	unsigned long to_page;
	unsigned long phys_addr;

	from_page = to_page = ((address>>20) & 0xffc);
	from_page += ((p->start_code>>20) & 0xffc);
	to_page += ((current->start_code>>20) & 0xffc);
/* is there a page-directory at from? */
	from = *(unsigned long *) from_page;
	if (!(from & 1))
		return 0;
	from &= 0xfffff000;
	from_page = from + ((address>>10) & 0xffc);
	phys_addr = *(unsigned long *) from_page;
/* is the page clean and present? */
	if ((phys_addr & 0x41) != 0x01)
		return 0;
	phys_addr &= 0xfffff000;
	if (phys_addr >= HIGH_MEMORY || phys_addr < LOW_MEM)
		return 0;
	to = *(unsigned long *) to_page;
	if (!(to & 1))
		if (to = get_free_page())
			*(unsigned long *) to_page = to | 7;
		else
			oom();
	to &= 0xfffff000;
	to_page = to + ((address>>10) & 0xffc);
	if (1 & *(unsigned long *) to_page)
		panic("try_to_share: to_page already exists");
/* share them: write-protect */
	*(unsigned long *) from_page &= ~2;
	*(unsigned long *) to_page = *(unsigned long *) from_page;
	invalidate();
	phys_addr -= LOW_MEM;
	phys_addr >>= 12;
	mem_map[phys_addr]++;
	return 1;
}

/*
 * share_page() tries to find a process that could share a page with
 * the current one. Address is the address of the wanted page relative
 * to the current data space.
 *
 * We first check if it is at all feasible by checking executable->i_count.
 * It should be >1 if there are other tasks sharing this inode.
 */
static int share_page(struct m_inode * inode, unsigned long address)
{
	struct task_struct ** p;

	if (inode->i_count < 2 || !inode)
		return 0;
	for (p = &LAST_TASK ; p > &FIRST_TASK ; --p) {
		if (!*p)
			continue;
		if (current == *p)
			continue;
		if (address < LIBRARY_OFFSET) {
			if (inode != (*p)->executable)
				continue;
		} else {
			if (inode != (*p)->library)
				continue;
		}
		if (try_to_share(address,*p))
			return 1;
	}
	return 0;
}

void do_no_page(unsigned long error_code,unsigned long address)
{
	int nr[4];
	unsigned long tmp;
	unsigned long page;
	int block,i;
	struct m_inode * inode;

	if (address < TASK_SIZE)
		printk("\n\rBAD!! KERNEL PAGE MISSING\n\r");
	if (address - current->start_code > TASK_SIZE) {
		printk("Bad things happen: nonexistent page error in do_no_page\n\r");
		do_exit(SIGSEGV);
	}
	page = *(unsigned long *) ((address >> 20) & 0xffc);
	if (page & 1) {
		page &= 0xfffff000;
		page += (address >> 10) & 0xffc;
		tmp = *(unsigned long *) page;
		if (tmp && !(1 & tmp)) {
			swap_in((unsigned long *) page);
			return;
		}
	}
	address &= 0xfffff000;
	tmp = address - current->start_code;
	if (tmp >= LIBRARY_OFFSET ) {
		inode = current->library;
		block = 1 + (tmp-LIBRARY_OFFSET) / BLOCK_SIZE;
	} else if (tmp < current->end_data) {
		inode = current->executable;
		block = 1 + tmp / BLOCK_SIZE;
	} else {
		inode = NULL;
		block = 0;
	}
	if (!inode) {
		get_empty_page(address);
		return;
	}
	if (share_page(inode,tmp))
		return;
	if (!(page = get_free_page()))
		oom();
/* remember that 1 block is used for header */
	for (i=0 ; i<4 ; block++,i++)
		nr[i] = bmap(inode,block);
	bread_page(page,inode->i_dev,nr);
	i = tmp + 4096 - current->end_data;
	if (i>4095)
		i = 0;
	tmp = page + 4096;
	while (i-- > 0) {
		tmp--;
		*(char *)tmp = 0;
	}
	if (put_page(page,address))
		return;
	free_page(page);
	oom();
}

void mem_init(long start_mem, long end_mem)
{
	int i;

	HIGH_MEMORY = end_mem;
	for (i=0 ; i<PAGING_PAGES ; i++)
		mem_map[i] = USED;
	i = MAP_NR(start_mem);
	end_mem -= start_mem;
	end_mem >>= 12;
	while (end_mem-->0)
		mem_map[i++]=0;
}

void show_mem(void)
{
	int i,j,k,free=0,total=0;
	int shared=0;
	unsigned long * pg_tbl;

	printk("Mem-info:\n\r");
	for(i=0 ; i<PAGING_PAGES ; i++) {
		if (mem_map[i] == USED)
			continue;
		total++;
		if (!mem_map[i])
			free++;
		else
			shared += mem_map[i]-1;
	}
	printk("%d free pages of %d\n\r",free,total);
	printk("%d pages shared\n\r",shared);
	k = 0;
	for(i=4 ; i<1024 ;) {
		if (1&pg_dir[i]) {
			if (pg_dir[i]>HIGH_MEMORY) {
				printk("page directory[%d]: %08X\n\r",
					i,pg_dir[i]);
				continue;
			}
			if (pg_dir[i]>LOW_MEM)
				free++,k++;
			pg_tbl=(unsigned long *) (0xfffff000 & pg_dir[i]);
			for(j=0 ; j<1024 ; j++)
				if ((pg_tbl[j]&1) && pg_tbl[j]>LOW_MEM)
					if (pg_tbl[j]>HIGH_MEMORY)
						printk("page_dir[%d][%d]: %08X\n\r",
							i,j, pg_tbl[j]);
					else
						k++,free++;
		}
		i++;
		if (!(i&15) && k) {
			k++,free++;	/* one page/process for task_struct */
			printk("Process %d: %d pages\n\r",(i>>4)-1,k);
			k = 0;
		}
	}
	printk("Memory found: %d (%d)\n\r",free-shared,total);
}
