#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>

#define ERR_GENERIC        -1
#define ERR_SUCCESS         0

const unsigned char ASM__NOP_2[] = { 0x66, 0x90 };
const unsigned char ASM__NOP_3[] = { 0x0f, 0x1f, 0x00 };
const unsigned char ASM__NOP_4[] = { 0x0f, 0x1f, 0x40, 0x00 };
const unsigned char ASM__NOP_5[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
const unsigned char ASM__NOP_6[] = { 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00 };
const unsigned char ASM__NOP_7[] = { 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00 };
const unsigned char ASM__NOP_8[] = { 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
const unsigned char ASM__NOP_9[] = { 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };


int trap_intercepted = 0;
int trap_setup_failed = ERR_GENERIC;

void sig_handler(int signo)
{
  if (signo == SIGTRAP) {
    trap_intercepted = 1;
  }
}

int init_sig_handler() {

    __sighandler_t ret = signal(SIGTRAP, sig_handler);
    
    if (ret == SIG_ERR) {
        return ERR_GENERIC;
    }
    
    return ERR_SUCCESS;
}

void test_debugger() {
    trap_setup_failed = init_sig_handler();

    //asm ("int $0x03;");

    __asm__ ("int $0x03");

    if (!trap_intercepted || trap_setup_failed) {
        printf("There's some debugger attached!!!");
        exit(0);
    }
}

int change_page_permission(void *addr) {

    int page_size = getpagesize();
    addr -= (unsigned long)addr % page_size;

    if (mprotect(addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == ERR_GENERIC) {
        return ERR_GENERIC;
    } else {
        return ERR_SUCCESS;
    }
}

void read_code(void *addr, int size) {

    for (int i=0; i < size; i++) {
        unsigned char *instruction = (unsigned char*)addr + i;
        printf("%02x ", *instruction);
    }
}

void overwrite_code(void *addr, int size, const unsigned char *new_code) {

    printf("\n");
    for (int i=0; i < size; i++) {
        unsigned char *instruction = (unsigned char*)addr + i;
        printf("%02x -> %02x\n", *instruction, new_code[i]);
        *instruction = new_code[i];
    }
}

void hidden_call() {
    //asm ("push %rax;");
    //asm ("pop %rax;");
    //asm ("pop %rax;");
    printf("\np1\n");
}

void public_call() {
    printf("\np2\n");
}


void obfuscated_call() {

    void *ptr = printf;
    ptr++;
    // asm (
    //     //"mov printf, %%edx;"
    //     "lea hidden_call, %%rax;"
    //     "lea public_call, %%rbx;"
    //     "push %%rax;"
    //     "jmp *%%rbx;"
    //     : "=r" (ptr)
    //     :
	// 	:"%rax", "rbx");
    
    printf("obfuscated_call_end");
}

int main(int argc, char **argv) {
    
    // test_debugger();
    
    // change_page_permission(read_code);

    // read_code(read_code, 4);

    // overwrite_code(read_code, 4, ASM__NOP_4);

    // read_code(read_code, 4);

    // hidden_call();
    // public_call();
    // obfuscated_call();

    // void *ptr = malloc(100);
    // memset(ptr, 0, 100);
    // printf("\nHello World!\n");

    printf("before entering asm section\n");
    // asm (
    //     //"mov printf, %%edx;"
    //     "lea hidden_call, %%rax;"
    //     // "lea public_call, %%rbx;"
    //     "lea label, %%rcx;"
    //     "push %%rcx;"
    //     "push %%rax;"
    //     // "jmp *%%rbx;"
    //     "jmp public_call;"
    //     "label:"
    //     :
    //     :
	// 	:);

    printf("about to exit from main\n");
    return 4;
}