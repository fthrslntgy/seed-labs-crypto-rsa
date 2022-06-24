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

	// Hex representation of 'Bu da ikinci gizli mesaj' is '427520646120696b696e63692067697a6c69206d6573616a'
	// message as m
	BIGNUM* m = BN_new();
	BN_hex2bn(&m, "427520646120696b696e63692067697a6c69206d6573616a");
	
	// results
	BIGNUM* encrypted = BN_new();
	BIGNUM* decrypted = BN_new();
	printBN("The plaintext: ", m);

	encrypted = rsa_encrypt(m, e, n);
	printBN("Encrypted: ", encrypted);

	decrypted = rsa_decrypt(encrypted, d, n);
	printf("Decrypted: ");
	printHX(BN_bn2hex(decrypted));
}