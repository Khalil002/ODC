#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <capstone/capstone.h>
#include <inttypes.h>

#define BUFFER_SIZE 0x100

void play()
{
    unsigned char buffer[BUFFER_SIZE];
    int (*shellcode_func)();
    csh handle;
    cs_insn *insn;
    size_t count, n_char, j;

    printf(" > ");
    memset(buffer, 0, BUFFER_SIZE);
    n_char = read(0, buffer, BUFFER_SIZE);
    if (buffer[n_char - 1] == '\n')
    {
        n_char--;
        buffer[n_char] = 0;
    }
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        puts("Capstone failed!");
        exit(-1);
    }
    count = cs_disasm(handle, buffer, n_char, 0x1000, 0, &insn);
    if (count > 0) 
    {
        for (j = 0; j < count; j++) 
        {
            if (strlen(insn[j].bytes) > 2)
            {
                printf("Instruction has %ld bytes: %s\t%s\n", 
                    strlen(insn[j].bytes), 
                    insn[j].mnemonic,
                    insn[j].op_str);
                exit(-2);
            }
        }
        cs_free(insn, count);
    } 
    else
    {
        puts("Failed to disassemble!");
        exit(-3);
    }
    puts("Good luck!!!");
    shellcode_func = (int (*)()) buffer;
    (int)(*shellcode_func)();
}

void init_buffers()
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void welcome()
{
    puts("Can you pop a shell with a shellcode made of 1 or 2 bytes instructions?");
}

void game()
{
    alarm(60);
    welcome();
    play();
}

int main (int argc, char *argv[])
{
    init_buffers();
    game();
}