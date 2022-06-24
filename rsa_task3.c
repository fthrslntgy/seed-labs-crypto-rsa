#include "mylib.c"

int main() {

	// first prime as p
	BIGNUM *p = BN_new();
	BN_hex2bn(&p, "C353136B52414B12B4149F7FA641AE97A07C98292D4358227DFE0EA3BC4DAD7F");
	
	// second prime as q
	BIGNUM *q = BN_new();
	BN_hex2bn(&q, "F555DEEF7084C34D2FB95C3B942BB4CCF06A8FD18CE63A87D63275CE06FE28BF");
	
	// mod as e
	BIGNUM *e = BN_new();
	BN_hex2bn(&e, "010001");

	// get private key as d
	BIGNUM* d = get_rsa_priv_key(p, q, e);
	printBN("Derived private key is: ", d);

	//get public key as n
	BIGNUM* n = big_mul(p, q);
	printBN("Derived public key from p and q is: ", n);
	
	// ciphertext as c
	BIGNUM* c = BN_new();
	BN_hex2bn(&c, "7AA0FF25F5D5C94FBEA7109F8AA34A43ADA883EF30CE12A4595BBD92D36D91FBE43A841400345177D6572F6587882FAB78549D6155500F9D319F892F8E74F07F");
	printBN("The ciphertext: ", d);

	// results
	BIGNUM* decrypted = BN_new();
	decrypted = rsa_decrypt(c, d, n);
	printf("Decrypted: ");
	printHX(BN_bn2hex(decrypted));
}