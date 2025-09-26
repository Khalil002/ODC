int main (){
    void *data;
    data = mmap(0, 0x1000,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    write(1, "Shellcode: ", 11);
    read(0, data, 0x200);
    register long rax __asm__("rax") = data;
    reset_register();
    asm("jmp %rax");
    return 0;
}