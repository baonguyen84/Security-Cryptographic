/*Header file for cryto program */

//Decrypt function
void decryption ();
//Encrypt function
void encryption ();
//Key generation function
void keyGeneration();
//Miller Rabin to find  large prime 
uint32_t prime(uint32_t num);
//square and multiply func to help quickly calculate  modular exponentiation result = (a^b) mod n
uint64_t squareMul(uint64_t a, uint64_t b, uint64_t n);
