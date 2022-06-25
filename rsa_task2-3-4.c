#include "mylib.c"

int main() {

	// TASK 2
	printf("### TASK 2 ###\n");

	// first prime as p
	BIGNUM *p = BN_new();
	BN_hex2bn(&p, "C353136B52414B12B4149F7FA641AE97A07C98292D4358227DFE0EA3BC4DAD7F");
	
	// second prime as q
	BIGNUM *q = BN_new();
	BN_hex2bn(&q, "F555DEEF7084C34D2FB95C3B942BB4CCF06A8FD18CE63A87D63275CE06FE28BF");

	//get public key as n from p and q (p*q)
	BIGNUM* n = big_mul(p, q);
	printBN("Derived public key (n) from p and q is --> ", n);
	
	// mod as e
	BIGNUM *e = BN_new();
	BN_hex2bn(&e, "010001");

	// Hex representation of 'Bu da ikinci gizli mesaj' is '427520646120696b696e63692067697a6c69206d6573616a'
	// message as m
	BIGNUM* m = BN_new();
	BN_hex2bn(&m, "427520646120696b696e63692067697a6c69206d6573616a");

	// get private key as d from p,q and e
	BIGNUM* d = get_rsa_priv_key(p, q, e);
	printBN("Derived private key (d) from p, q and e is --> ", d);
	
	// results
	printBN("The plaintext --> ", m);
	
	BIGNUM* encrypted = BN_new();
	encrypted = rsa_encrypt(m, e, n);
	printBN("Encrypted --> ", encrypted);

	BIGNUM* decrypted = BN_new();
	decrypted = rsa_decrypt(encrypted, d, n);
	printBN("Decrypted (to provide) --> ", decrypted);
	printf("Hex mean of decrypted --> ");
	printHX(BN_bn2hex(decrypted));

	// TASK 3
	printf("\n\n### TASK 3 ###\n");
	printf("--p, q, e (therefore derived d and n) values are same with task 2.--\n");

	// ciphertext as c
	BIGNUM* c = BN_new();
	BN_hex2bn(&c, "7AA0FF25F5D5C94FBEA7109F8AA34A43ADA883EF30CE12A4595BBD92D36D91FBE43A841400345177D6572F6587882FAB78549D6155500F9D319F892F8E74F07F");
	printBN("The ciphertext --> ", c);

	// results
	decrypted = rsa_decrypt(c, d, n);
	printBN("Decrypted --> ", decrypted);
	printf("Hex mean of decrypted --> ");
	printHX(BN_bn2hex(decrypted));


	// TASK 4
	printf("\n\n### TASK 4 ###\n");
	printf("--p, q, e (therefore derived d and n) values are same with task 2.--\n");

	// Hex representation of 'Sana 1 milyon lira borcum var.' is '53616e612031206d696c796f6e206c69726120626f7263756d207661722e'
	// message as m1
	BIGNUM* m1 = BN_new();
	BN_hex2bn(&m1, "53616e612031206d696c796f6e206c69726120626f7263756d207661722e");

	// Hex representation of 'Sana 2 milyon lira borcum var.' is '53616e612032206d696c796f6e206c69726120626f7263756d207661722e'
	// message 2 as m2
	BIGNUM* m2 = BN_new();
	BN_hex2bn(&m2, "53616e612032206d696c796f6e206c69726120626f7263756d207661722e");
	
	// encrypt messages as signatures s1 and s2
	BIGNUM* s1 = BN_new();
	s1 = rsa_encrypt(m1, d, n);
	printBN("Signature --> ", s1);

	BIGNUM* s2 = BN_new();
	s2 = rsa_encrypt(m2, d, n);
	printBN("Signature for changed text (1 to 2) --> ", s2);
	printf("--Although we changed a single character in the main text, we noticed a huge change in the signatures of the texts.\n");
	printf("Considering that we also obtain the signatures of the texts by encryption, we have seen that a small change in the plaintexts can completely change the ciphertext.--\n");
	printf("\n");

	// decrypt messages to provide
	BIGNUM* decrypted1 = BN_new();
	decrypted1 = rsa_decrypt(s1, e, n);
	printBN("Decrypted (to provide): ", decrypted1);
	printf("Hex mean of decrypted: ");
	printHX(BN_bn2hex(decrypted1));
	
	// decrypt with second signature
	BIGNUM* decrypted2 = BN_new();
	decrypted2 = rsa_decrypt(s2, e, n);
	printBN("Decrypted of changed text (to provide): ", decrypted2);
	printf("Hex mean of decrypted: ");
	printHX(BN_bn2hex(decrypted2));
}