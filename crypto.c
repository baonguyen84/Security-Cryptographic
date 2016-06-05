/* CS 427 Project 2
Public key cryptosystem
bao.nguyen@wsu.edu
SID 11354901
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include "crypto.h"

#define _POSIX_C_SOURCE 200809L
#define BUFFERSIZE 64		//buffer for large number
#define KEYBUFFER 128		//buffer for key file
#define MODEBUFFER 4		//buffer for mode input
#define PTEXT "ptext.txt"   //plaintext	file name
#define CTEXT "ctext.txt"	//ciphertext file name
#define DTEXT "dtext.txt"	//decryption text file name
#define PUBKEY "pubkey.txt" //public key file name
#define PRIKEY "prikey.txt"	//private key file name

//Main function
int main(int argc, char** argv){
	char mode[MODEBUFFER]; // 3 mode k: key generation, e: encryption and d: decruption
	printf("Please type in choosing mode: k: Key Generation \n e: Encryption \n d: Decryption \n");
	fflush(stdout); //flush input to terminal
	fgets(mode, MODEBUFFER, stdin);
	if(mode[0] == 'k'){
		printf("Key Generation mode \n");
		keyGeneration();
	}else if(mode[0] == 'e'){
		printf("Encryption mode \n");
		encryption();			
	}else if(mode[0] == 'd'){
		printf("Decryption mode\n");
		decryption();
	}else{
		printf("Usage: Enter 'k' or 'd' or 'e' only \n");
		exit(0);
	}	

	return 0;
} 

 //Miller Rabin to find  large prime 
//num - 1 = (2^r)*d 
uint32_t prime(uint32_t num){
	//base case num < 3
	if (num == 1 || num == 2) return 1; //prime
	if (num % 2 == 0) return 0; //even num, divide 2 -> not prime

	//factoring power of 2 from num -1	
	int k = 1, q = (num - 1)/2;
	while (q%2 == 0) {
		k++;
		q /= 2;
	}
	//pick random number in range [2, num -2]
	uint32_t r = drand48()*(num - 3) + 2;
	if (squareMul(r, q, num) == 1)
		return 1;
	int inc = 1;
	for (int i = 0; i < k; i++) { //iteration
		if (squareMul(r, inc*q, num) == num - 1) return 1;
		inc *= 2;
	}
	return 0;
}

//square and multiply func to help quickly calculate  modular exponentiation result = (a^b) mod n
uint64_t squareMul(uint64_t a, uint64_t b, uint64_t n){
	uint64_t res = 1; //initialize result
	for (int i = sizeof(b)*8-1; i >= 0; i--) {
		res = (res * res) % n; //square
		if ((b >> i) & 1) {
			res = (res * a) % n; //multiply
		}
	}
	return res;
}

//Key generation function
void keyGeneration(){
	//promt for input
	printf("Enter a random number: \n");
	char seedRandom[BUFFERSIZE];
	fflush(stdout);
	fgets(seedRandom, BUFFERSIZE, stdin);
	long int seed = atoi(seedRandom);
	srand48(seed);
	
	uint32_t p;
	uint32_t g = 2;
	//TODO: find p by MillerRabin alogrithm
	do{
		uint32_t q = lrand48();
		uint32_t temp = q;
		q &= 0x7FFFFFFF;
		q |= (1 << 30);
		q |= 1;
	//if not prime [and  still less than 2147483647 (0x7FFFFFFF) - max 32 bit Number] then increment 1
		while(q%12 != 5 && !prime(q) && q < 0x7FFFFFFF){
			q +=1;
		}
		//if still not find then back to first number we choose
		if (q %12 != 5 && !prime(q)){ 
			q = temp;
		}
	//then gp down while it is not prime and  bigger than 0x18031984 <-just big number as my year of birth) then decrement 1
		while(q%12 != 5 && !prime(q) && q > 0x13181984){
			q -=1;
		}
		//increase q to find p
		p = 2*q + 1;

	}while(!prime(p));
	//printf("Safe Prime is %u \n", p);
	uint32_t d = drand48()*(p - 2 ) + 1;
	uint32_t e2 = squareMul(g, d, p); //e2 = (g^d) mod p
	//write output to pubkey.txt and prikey.txt
	FILE* out = fopen(PUBKEY, "w");
	fprintf(out, "%u, %u, %u", p, g, e2);
    printf("Public key p, g, e2: %u, %u, %u \n", p, g, e2);
	fclose(out);
	out = fopen(PRIKEY, "w");
	fprintf(out, "%u, %u, %u", p, g, d);
    printf("Private key p, g, d: %u, %u, %u \n", p, g, d);
	fclose(out);
    printf("Done key generating.\n");
}


//Encrypt function
void encryption () {
	printf("Encrypting ... \n");
	uint32_t p, g, e2; //read key from file
	FILE* fp= fopen(PUBKEY, "r");
	char str[KEYBUFFER];
	const char s[2] = ", ";
	char *token;
	if(fp == NULL){
		perror("Error to open file \n");
		exit(1);
	}
	if(fgets(str, KEYBUFFER, fp)!= NULL){ 
		token = strtok(str, s); 
		p = atoi(token); 
		g = atoi(strtok(NULL, s));
		e2 = atoi(strtok(NULL, s));
	  }
	fclose(fp);
	char mbuffer[4]; //store block plaintext
	int bytes; 
	FILE* outfile = fopen(CTEXT, "w"); //open cipher text  fileto save later
	int plaintext = open(PTEXT, O_RDONLY);
	bytes = read(plaintext, mbuffer, sizeof(mbuffer));
	//printf("Cipher text format [C1, C2]: \n");
	while (bytes > 0) {
		uint64_t m = 0;
		int i;
		for (i = 0; i < bytes; i++) {
			m <<= 8;
			m |= mbuffer[i];
		}
		//for multi block m encrypt C1 and C2 then save to cipher text file
		for (int j = i; j < sizeof(mbuffer); j++) m <<= 8;
		uint32_t k = drand48() * (double) ((p - 2) + 1);
		uint32_t C1 = squareMul(g, k, p);
		uint32_t C2 = (squareMul(e2, k, p) * (m % p)) % p;
		fprintf(outfile, "%u, %u\n", C2, C1);
		//printf("%u, %u \n",C2, C1); 
		bytes = read(plaintext, mbuffer, sizeof(mbuffer));
	}
	fclose(outfile);
	close(plaintext);
	printf("Done encrypting! Open ctext file for more info \n");
}

//Decrypt function

void decryption () {
	printf("Decrypting ...\n");
	FILE* fp= fopen(PRIKEY, "r");
	char str[KEYBUFFER];
	uint32_t p, d; //read key from file
	const char s[2] = ", ";
	char *token;
	if(fp == NULL){
		perror("Error to open file \n");
		exit(1);
	}
	if(fgets(str, KEYBUFFER, fp)!= NULL){ 
		token = strtok(str, s); 
		p = atoi(token); 
		atoi(strtok(NULL, s));
		d = atoi(strtok(NULL, s));
	  }
	fclose(fp);

	FILE* ciphertext = fopen(CTEXT, "r");
	char cbuffer[64];
	FILE* outfile = fopen(DTEXT, "w");
	printf("Decrypted text: \n");
	//printf("p = %u, d = %u \n", p, d);

	while (fgets(cbuffer, sizeof(cbuffer), ciphertext) != NULL){
        uint32_t C1, C2;
        token = strtok(cbuffer, s); 
        C2 = atoi(token); 
        C1 = atoi(strtok(NULL, s));
        //printf("C1 = %u, C2 = %u \n", C1, C2);
        uint64_t part1 = squareMul(C1, p - 1 - d, p);
        uint64_t part2 = C2 % p;
        uint32_t m = (part1 * part2) % p;
        //printf("%u \n", m);
        char mbuffer[sizeof(m) + 1];
        mbuffer[sizeof(m)] = '\0';
        for (int i = 0; i < sizeof(m); i++) {
            int j = sizeof(m) - i - 1;
            uint32_t temp = m >> (j * 8);
            int c = temp & 0xFF;
            mbuffer[i] = c;
        }
        fprintf(outfile, "%s", mbuffer);
        printf("%s", mbuffer);
    }
	    printf("\n");
	    fclose(outfile);
	    fclose(ciphertext);
}

