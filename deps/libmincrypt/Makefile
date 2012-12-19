all:
	gcc -c rsa.c -o rsa.o
	gcc -c sha.c -o sha.o
	ar rcs libmincrypt.a rsa.o sha.o
	gcc -c -fPIC rsa.c -o rsaf.o
	gcc -c -fPIC sha.c -o shaf.o
	gcc -shared -Wl,-soname,libmincrypt.so.1 -o libmincrypt.so.1.0.1 rsaf.o shaf.o

clean:
	rm -f *.o *.so.* *.a
