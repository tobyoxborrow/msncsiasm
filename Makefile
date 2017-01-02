default:
	nasm -f elf32 -o msncsi.o msncsi.nasm
	ld -m elf_i386 -o msncsi msncsi.o
clean:
	rm msncsi msncsi.o
