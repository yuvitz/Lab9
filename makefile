all: Task0b

Task0b: Task0b.o
	ld -m elf_i386 Task0b.o -o Task0b

Task0b.o: Task0b.s
	nasm -f elf Task0b.s -o Task0b.o
	
.PHONY: clean
clean:
	rm -f *.o Task0b