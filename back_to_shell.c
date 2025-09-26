int main (){
    void *data;
    data = mmap(0, 0x1000, 7, 0x22, -1, 0);
    write(1, "Shellcode: ", 11);
    read(0, data, 0x200);
    register long rax __asm__("rax") = data;
    reset_register();
    asm("jmp %rax");
    return 0;
}

int _start(){
    main();
    exit(0);
}