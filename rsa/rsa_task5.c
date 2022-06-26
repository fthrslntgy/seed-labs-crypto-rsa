#include "mylib.c"

int main() {

	// Hex representation of 'Launch a missile.' is '4c61756e63682061206d697373696c652e0d0a'
	// message as m
	BIGNUM* m = BN_new();
	BN_hex2bn(&m, "4c61756e63682061206d697373696c652e");
	printBN("Message is: ", m);
	printf("Hex mean of message: ");
	printHX(BN_bn2hex(m));
	printf("\n");

	// signatures as s1 and s2
	BIGNUM* s1 = BN_new();
	BN_hex2bn(&s1, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	BIGNUM* s2 = BN_new();
	BN_hex2bn(&s2, "4E96B0012354774DD6C90215F0A51D356D08D9D64064C8703962C414378CE7F3");
	
	// mod as e
	BIGNUM* e = BN_new();
	BN_hex2bn(&e, "010001");
		
	// public key as n
	BIGNUM* n = BN_new();
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

	printf("--The verification algorithm is to compute S^e mod n and then compare the result with the message M--\n");
	
	// decrypt with first signature
	BIGNUM* decrypted1 = BN_new();
	decrypted1 = rsa_decrypt(s1, e, n);
	printBN("Verifying with S1: ", decrypted1);
	printf("Hex mean of decrypted S1: ");
	printHX(BN_bn2hex(decrypted1));
	
	// decrypt with second signature
	BIGNUM* decrypted2 = BN_new();
	decrypted2 = rsa_decrypt(s2, e, n);
	printBN("Verifying with S2: ", decrypted2);
	printf("Hex mean of decrypted: ");
	printHX(BN_bn2hex(decrypted2));
	printf("\n");

	// compare decryptions with message and find which signature belongs to Alice
	if (BN_cmp(m, decrypted1) == 0)
		printf("S1 verified that its the signature of Alice because its decryption gives the message us. Decryption of S2 is meanless.\n");
	else if (BN_cmp(m, decrypted2) == 0)
		printf("S2 verified that its the signature of Alice because its decryption gives the message us. Decryption of S1 is meanless.\n");
	else
		printf("Both are not the signatures of Alice. Their decryptions are meanless.\n");
}