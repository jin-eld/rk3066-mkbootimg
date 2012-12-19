all:
	gcc -Ideps/libmincrypt -Ldeps/libmincrypt unpackbootimg.c -o unpackbootimg -lmincrypt
	gcc -ggdb -Ideps/libmincrypt -Ldeps/libmincrypt mkbootimg.c -o mkbootimg -lmincrypt

clean:
	rm -f mkbootimg unpackbootimg
