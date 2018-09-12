//	Erman Sahin Tatar   -> CBC Mode Encryption Algorithm. 
//	Enterprise Network Security Programing Project 1
//	Instructor: Guanhua Yan
//	Due date: February 13, Tuesday extension Due Date 27 February. 

/*
Cipher block chaining (CBC) is a mode of operation
for a block cipher (one in which a sequence of bits are encrypted as a single unit or block
with a cipher key applied to the entire block). Cipher block chaining uses what is known as an initialization vector
(IV) of a certain length. One of its key characteristics is that
it uses a chaining mechanism that causes the decryption of a block of ciphertext to depend on all the preceding ciphertext blocks.
As a result, the entire validity of all preceding blocks is contained in the immediately previous ciphertext block.
A single bit error in a ciphertext block affects the decryption of all subsequent blocks. 
Rearrangement of the order of the ciphertext blocks causes decryption to become corrupted. 
Basically, in cipher block chaining, each plaintext block is XORed (see XOR) with the immediately previous ciphertext block,
and then encrypted.
*/





#include "fscrypt.h"
#include <iostream>
#include <cstring>
#include <stdlib.h> 
#include <math.h> 

using namespace std;




// Encrypt plaintext of length bufsize. Use keystr as the key.
void * fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){ 

	// First step, we need to decleare INITIALIZATION VECTOR
	unsigned char initial_vector[8] = {0};

	// Second step, we need to generate key. 	
	BF_KEY key[strlen(keystr)];		
	BF_set_key(key, strlen(keystr), (const unsigned char*) keystr);


	// We need to calculate plaintext which is sent as parameter. 
	char* pointerText = (char*) plaintext;	
	int plainTextLength = strlen(pointerText);
	char* plainText;


	// Cipher text, we will need space reserved for it. 
	int padLength = 0; 
	unsigned char* out;



	if (plainTextLength % BLOCKSIZE != 0){
	 
		// we will do padding amount of divide of "8" bit blocks.   
		padLength = BLOCKSIZE - (plainTextLength % BLOCKSIZE);
		
		out = (unsigned char*) malloc(plainTextLength + padLength);

		char p = '0' + padLength;		
			
		plainText = (char*) malloc(plainTextLength + padLength);

		// Plain text padded with length of the blank bytes in last block
		int plaintext_counter = 0;
		int padding_counter = 0;

		while(plaintext_counter < plainTextLength){

			plainText[plaintext_counter] = pointerText[plaintext_counter];
			plaintext_counter = plaintext_counter + 1; 

		}

		while(padding_counter < padLength){

			plainText[plainTextLength + padding_counter] = p;
			padding_counter = padding_counter + 1;
		}
		
		

	}else{
		
		out = (unsigned char*) malloc(plainTextLength);
		
	}	


	unsigned char previousCipherBlock[8] = {0};	
	char plainTextBlock[8] = {0};
	unsigned char cipherTextBlock[8] = {0};	
	char xorResult[8];
	double bSize = (double)	BLOCKSIZE;

	// Encription takes place here

	int enc_counter = 0;

	while( enc_counter < ceil(plainTextLength/ bSize) ){

		int bit = 0;
		while(bit < BLOCKSIZE){

			plainTextBlock[bit] = plainText[(enc_counter * 8) + bit];

			bit = bit + 1;
		} 

		// initial vector should be used in first iteration
		if (enc_counter == 0){
			 

				for (int i = 0; i < BLOCKSIZE; i++){
		 
					xorResult[i] = initial_vector[i] ^ plainTextBlock[i];
				}
				
		}else{
			 
				for (int i = 0; i < BLOCKSIZE; i++){
		 
		 			xorResult[i] = previousCipherBlock[i] ^ plainTextBlock[i];
				}
		}

		const unsigned char* constXorResult = (const unsigned char*) xorResult;
		
		//blowfish encrypt. 
		BF_ecb_encrypt( constXorResult, cipherTextBlock, key, BF_ENCRYPT);

		for (int bitc = 0; bitc < BLOCKSIZE; bitc++)
		{
			previousCipherBlock[bitc] = cipherTextBlock[bitc];
			out[(enc_counter * 8) + bitc] = cipherTextBlock[bitc];
		}

		enc_counter = enc_counter + 1;
	}

	// Number of valid bytes kept in resultlen
	*resultlen = plainTextLength;
	
	return out;


}



// Decrypt ciphertext of length bufsize. Use keystr as the key.
void * fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){

	// Initialization vector
	unsigned char initial_vector[8] = {0};

	// Key Generation	
	BF_KEY key[strlen(keystr)];		
	BF_set_key(key, strlen(keystr), (const unsigned char*) keystr);	

	// Number of valid bytes assigned to resultlen
	*resultlen = bufsize + 1;

	// Space reserved for plain text 
	unsigned char* out;
	out = (unsigned char*) malloc(bufsize);

	char* cipherText = (char*) ciphertext;	
	double bSize = (double)	BLOCKSIZE;
	unsigned char previousCipherBlock[8] = {0};
	unsigned char cipherTextBlock[8] = {0};


	


	// Decryption starts 
	int dec_counter = 0;

	while(dec_counter < ceil(bufsize/ bSize)){

		for (int k = 0; k < BLOCKSIZE; k++) cipherTextBlock[k] = cipherText[(dec_counter * 8) + k];

		int bit = 0; 
		while(bit < BLOCKSIZE){

			cipherTextBlock[bit] = cipherText[(dec_counter * 8) + bit];

			bit = bit + 1;
		}

		const unsigned char* constCipherTextBlock = (const unsigned char*) cipherTextBlock;
		unsigned char plainTextBlock[8] = {0};
		BF_ecb_encrypt(constCipherTextBlock, plainTextBlock, key, BF_DECRYPT);
		char* plainTextBlockForXor = (char*) plainTextBlock;
		char xorResult[8];

		if (dec_counter == 0){
		
			for (int i = 0; i < BLOCKSIZE; i++){
		 
					xorResult[i] = initial_vector[i] ^ plainTextBlockForXor[i];
			}
		
		}else{
		
			for (int i = 0; i < BLOCKSIZE; i++){
		 
					xorResult[i] = previousCipherBlock[i] ^ plainTextBlockForXor[i];
			}
		
		}

		int bitc = 0;
		while(bitc < BLOCKSIZE){

			out[(dec_counter * 8) + bitc] = xorResult[bitc];
			previousCipherBlock[bitc] = cipherText[(dec_counter * 8) + bitc];

			bitc = bitc + 1;
		}

		dec_counter = dec_counter + 1;
	}

	unsigned char* result = (unsigned char*) malloc(bufsize);
	
	for (int i = 0; i < bufsize; i++){
		 result[i] = out[i];
	}

	return result;






}








