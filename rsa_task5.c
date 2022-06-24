#include "mylib.c"

int main() {
	
	// public key as n
	BIGNUM* n = BN_new();
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	
	// mod as e
	BIGNUM* e = BN_new();
	BN_hex2bn(&e, "010001");

	// signatures as s1 and s2
	BIGNUM* s1 = BN_new();
	BIGNUM* s2 = BN_new();	
	BN_hex2bn(&s1, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	BN_hex2bn(&s2, "4E96B0012354774DD6C90215F0A51D356D08D9D64064C8703962C414378CE7F3");
	
	// Hex representation of 'Launch a missile.' is '4c61756e63682061206d697373696c652e0d0a'
	// message as m
	BIGNUM* m = BN_new();
	BN_hex2bn(&m, "4c61756e63682061206d6973736c652e");

	// decrypt the message
	BIGNUM* decrypted = BN_new();
	decrypted = rsa_decrypt(s1, e, n);
	printf("Decrypted with s1: ");
	printHX(BN_bn2hex(decrypted));
	printf("\n");
	
	// decrypt with second signature
	BIGNUM* decrypted2 = BN_new();
	decrypted2 = rsa_decrypt(s2, e, n);
	printf("Decrypted with s2: ");
	printHX(BN_bn2hex(decrypted2));
}