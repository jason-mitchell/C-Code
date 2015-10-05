//       
//               Filename: aes.h
//               Description: Header file for AES Crypto Library
//
//
//               Version: 1.0
//               Date: 02 August 2013
//
//
//
//
//------------------------------------------------------------------------------------------------------------------------------------



#ifndef AES_H_
#define AES_H_

// Definitions
//-------------
#define MAX_LENGTH	16






// External, static or other variables
//--------------------------------------





// Function Prototypes
//---------------------

void cipher_AES(unsigned char *Plain_Data, unsigned char KeyIndex);
void decipher_AES(unsigned char *Plain_Data, unsigned char KeyIndex);



 



#endif