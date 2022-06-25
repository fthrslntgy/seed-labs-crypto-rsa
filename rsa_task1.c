#include "mylib.c"

int main() {

	// public key as n
	BIGNUM* n = BN_new();
	BN_hex2bn(&n, "BB300643E39AA365612115898C2737D969635148A40AAAD9F2A92E60A7BB1BB7DA9A09F339FE02761FF451FF0FAFAFEA1C792D3C0114B2D4234FCFEABF1249C1");
	
	// mod as e
	BIGNUM* e = BN_new();
	BN_hex2bn(&e, "0D88C3");

	// Hex representation of 'Acayip gizli bir mesaj!' is '4163617969702067697a6c6920626972206d6573616a21'
	// message as m
	BIGNUM* m = BN_new();
	BN_hex2bn(&m, "4163617969702067697a6c6920626972206d6573616a21");

	// private key as d
	BIGNUM* d = BN_new();
	BN_hex2bn(&d, "8D017DAF61EB9E6E08A74841F2F9B2F50D6913D605C98E416E06D8441DDBE94F5F058E2FF8B629B59C98D4A6B799909455018CDE39C9FC3A4A74A6E483E45C07");
	
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
}