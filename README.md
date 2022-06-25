### Compiling and running
```bash
gcc rsa_task1.c -lcrypto -o rsa_task1.out
./rsa_task1.out
```

### Important Notes
- mylib.c includes common functions used by 'rsa_task*.c' files like printHX, printBN, rsa_encrypt, rsa_decrypt etc.
- Task 2, 3 and 4 uses same n, d and e values therefore this tasks' solutions are in same file.
- Text messages are converted to hex automatically (not in code) and indicated at comment lines.

