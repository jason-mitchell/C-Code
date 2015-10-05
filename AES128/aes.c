//
//
//          Filename: aes.c
//          Function: AES Encryption library
//
//          Version: 1.0.0.0
//          This code is derived from an AES library found in the most unlikely of places, Zilog's website (www.zilog.com)
//          It is small, compact and is exactly what is needed for an embedded system. Current implementations in the Linux kernel suffer
//          from the same bloat I see everywhere due to lazy programmers. I don't have > 1Mbyte of FLASH and RAM to just carelessly allocate
//          because the Linux programmers are too lazy to optimize the matrix operations
//
//          This code is originally intended for a Zilog Z8 microcontroller. It is the most efficient implementation of AES I have
//          ever seen. You will not find a more code and memory efficient implementation anywhere
//                  Code size: 1944 bytes  RAM size 192 bytes- will fit even the entry level HCS08 micros!
//
//          Freescale also have a library but are anally retentive about it so that is another nail in their coffin.
//
//          Portions of code COPYRIGHT (C)2012 ZILOG INCORPORATED
//
//          Notes:
//          -------------------
//          02-08-13: Start porting code, removed only linker declarations for Zilog's toolchain as they are not used here 
//          13-08-13: Fixed bug on line 282- decrypt working perfect now.
//          17-08-13: Adapted code to use selectable keys, where key index 0 is always the same regardless of firmware change
//
//
//
//--------------------------------------------------------------------------------------------------------------------------------------

#include "aes.h"
#include "crypto_keys.h"



//FIPS 197 S_Box used for Substitute bytes S_Box
const unsigned char S_Box[256] =   
{ 
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; 

//FIPS inv_S_Box used for inv_Substitute bytes inv_S_Box
const unsigned char inv_S_Box[256] =
{ 
0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// This is a turn constant for generating the 176 byte expanded key. DO NOT ALTER- it is correct!
const unsigned char R_Con[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

unsigned char KeyGen[176];

//------------------------------------------------------------------------------------------------
// Name: Generate_Key
// Function: Expands the R_Key
//------------------------------------------------------------------------------------------------
void Generate_Key(unsigned char KeyIndex)
{
	unsigned char temp_byte0;
	unsigned char ii;
	unsigned char x;

              
          // Load key as per index...          
          for (ii = 0; ii  <MAX_LENGTH; ii++){
          
                    switch(KeyIndex){
                              case 0:
                              KeyGen[ii] = Base_Key[ii];
                              break;
                              
                              case 1:
                              KeyGen[ii] = Key1[ii];
                              break;
                              
                              default:
                              KeyGen[ii] = Base_Key[ii];
                                                                                         
                    }                    
          }
	
    for (ii=1;ii<11;ii++)
	{
        temp_byte0 = KeyGen[ii*MAX_LENGTH - 4];
        KeyGen[ii*MAX_LENGTH + 0] = S_Box[KeyGen[ii*MAX_LENGTH - 3]]^KeyGen[(ii-1)*MAX_LENGTH + 0]^R_Con[ii];
		for(x=1;x<3;x++)
		{
			KeyGen[ii*MAX_LENGTH + x] = S_Box[KeyGen[ii*MAX_LENGTH - (3-x)]]^KeyGen[(ii-1)*MAX_LENGTH + x];
		}
		KeyGen[ii*MAX_LENGTH + 3] = S_Box[temp_byte0                  ]^KeyGen[(ii-1)*MAX_LENGTH + 3];
		for(x=4;x<MAX_LENGTH;x++)
		{
			KeyGen[ii*MAX_LENGTH + x] = KeyGen[(ii-1)*MAX_LENGTH + x]^KeyGen[ii*MAX_LENGTH + (x-4)];
		}
  }
}

// Name: G_Multiply
// Function: x2 in galois field
//-----------------------------------------
unsigned char G_Multiply(unsigned char value)
{
	if (value & 0x80)
	{
		value = value << 1;
		return (value^0x1b);
	} 
	else
		return value<<1;
}


// Name: mix_column
// Function: Used in the encryption- TL;TEH - See Wikipedia
//-------------------------------------------------------------
void mix_column(unsigned char *Plain_Data)
{
	unsigned char x;
	unsigned char temp_byte0, temp_byte1, temp_byte2;    //mixcolums
	for(x=0;x<15;x+=4)
	{
		temp_byte0 = Plain_Data[x] ^ Plain_Data[x+1] ^ Plain_Data[x+2] ^ Plain_Data[x+3];
		temp_byte1 = Plain_Data[x];

		temp_byte2 = Plain_Data[x]^Plain_Data[x+1]; 
		temp_byte2=G_Multiply(temp_byte2); 
		Plain_Data[x+0] = Plain_Data[x+0] ^ temp_byte2 ^ temp_byte0;
		
		temp_byte2 = Plain_Data[x+1]^Plain_Data[x+2]; 
		temp_byte2=G_Multiply(temp_byte2); 
		Plain_Data[x+1] = Plain_Data[x+1] ^ temp_byte2 ^ temp_byte0;
		
		temp_byte2 = Plain_Data[x+2]^Plain_Data[x+3]; 
		temp_byte2=G_Multiply(temp_byte2); 
		Plain_Data[x+2] = Plain_Data[x+2] ^ temp_byte2 ^ temp_byte0;
		
		temp_byte2 = Plain_Data[x+3]^temp_byte1;     
		temp_byte2=G_Multiply(temp_byte2); 
		Plain_Data[x+3] = Plain_Data[x+3] ^ temp_byte2 ^ temp_byte0;
	}	
}

// Name: add_S_Box_and_shift
// Function: Add round key, shift rows and substitute byte. Done in 10 rounds
//---------------------------------------------------------------------------------------------
void add_S_Box_and_shift(unsigned char *Plain_Data, unsigned char turn)
{
	unsigned char x;
	unsigned char temp_byte0, temp_byte1;
	//row 0
	for(x=0;x<15;x+=4)
	{
		Plain_Data[x]  = S_Box[(Plain_Data[x] ^ KeyGen[(turn*MAX_LENGTH) +  x])];
	}
    //row 1
    temp_byte0 = Plain_Data[1] ^ KeyGen[(turn*MAX_LENGTH) + 1];
	for(x=1;x<12;x+=4)
	{
		Plain_Data[x]  = S_Box[(Plain_Data[x+4] ^ KeyGen[(turn*MAX_LENGTH) +  x+4])];
	}
    Plain_Data[13]  = S_Box[temp_byte0];
    //row 2
    temp_byte0 = Plain_Data[2] ^ KeyGen[(turn*MAX_LENGTH) + 2];
    temp_byte1 = Plain_Data[6] ^ KeyGen[(turn*MAX_LENGTH) + 6];
    Plain_Data[ 2]  = S_Box[(Plain_Data[10] ^ KeyGen[(turn*MAX_LENGTH) + 10])];
    Plain_Data[ 6]  = S_Box[(Plain_Data[14] ^ KeyGen[(turn*MAX_LENGTH) + 14])];
    Plain_Data[10]  = S_Box[temp_byte0];
    Plain_Data[14]  = S_Box[temp_byte1];
    //row 3
	temp_byte0 = Plain_Data[15] ^ KeyGen[(turn*MAX_LENGTH) + 15];
	for(x=15;x>3;x-=4)
	{
		Plain_Data[x]  = S_Box[Plain_Data[x-4] ^ KeyGen[(turn*MAX_LENGTH) +  x-4]];
	}
	Plain_Data[ 3]  = S_Box[temp_byte0];
}

// Name:  inv_add_S_Box_and_shift
// Function: inv of Add round key, shift rows and substitute byte. Done in 10 rounds
//---------------------------------------------------------------------------------------------
void inv_add_S_Box_and_shift(unsigned char *Plain_Data, unsigned char turn)
{
	unsigned char x;
	unsigned char temp_byte0, temp_byte1;

	//row 0
	for(x=0;x<15;x+=4)
	{
		Plain_Data[x]  = inv_S_Box[Plain_Data[x]] ^ KeyGen[(turn*MAX_LENGTH) +  x];
	}
	//row 1
	temp_byte0 = inv_S_Box[Plain_Data[13]] ^ KeyGen[(turn*MAX_LENGTH) +  1];
	for(x=13;x>1;x-=4)
	{
		Plain_Data[x]  = inv_S_Box[Plain_Data[x-4]] ^ KeyGen[(turn*MAX_LENGTH) +  x];
	}
	Plain_Data[ 1]  = temp_byte0;
	//row 2
	temp_byte0 = inv_S_Box[Plain_Data[ 2]] ^ KeyGen[(turn*MAX_LENGTH) + 10];
	temp_byte1 = inv_S_Box[Plain_Data[ 6]] ^ KeyGen[(turn*MAX_LENGTH) + 14];
	Plain_Data[ 2]  = inv_S_Box[Plain_Data[10]] ^ KeyGen[(turn*MAX_LENGTH) +  2];
	Plain_Data[ 6]  = inv_S_Box[Plain_Data[14]] ^ KeyGen[(turn*MAX_LENGTH) +  6];
	Plain_Data[10]  = temp_byte0;
	Plain_Data[14]  = temp_byte1;
	//row 3
	temp_byte0 = inv_S_Box[Plain_Data[ 3]] ^ KeyGen[(turn*MAX_LENGTH) + 15];
	for(x=3;x<15;x+=4)
	{
		Plain_Data[x]  = inv_S_Box[Plain_Data[x+4]] ^ KeyGen[(turn*MAX_LENGTH) +  x];
	}
	Plain_Data[15]  = temp_byte0;
}

// CRYPTO FUNCTIONS PROPER
//--------------------------------------------------------------------------------------------------------------------------------------

// Name: cipher_AES
// Function: Encrypts a byte array of 16 bytes using the AES standard
// Parameters: Source/Destination array where data is to be encrypted to
// Returns: void
//--------------------------------------------------------------------------

void cipher_AES(unsigned char *Plain_Data, unsigned char KeyIndex)
{
	unsigned char x;
	unsigned char turn;

	Generate_Key(KeyIndex);       //expand the R_Key into 176 bytes
	for (turn = 0; turn < 9; turn ++)
	{
		//addturnkey, S_Box and shiftrows
		add_S_Box_and_shift(Plain_Data, turn);
		// mixcolums
		mix_column(Plain_Data);

	 }
	  //10th turn without mixcols
	 add_S_Box_and_shift(Plain_Data, turn);
	  //last addturnkey
	 for(x = 0; x < 16; x++)
	 {
		 Plain_Data[ x]^=KeyGen[160+x];
	 }
}
// Name: decipher_AES
// Function: Decrypts a byte array of 16 bytes using the AES standard
// Parameters: Source/Destination array where data is to be decrypted to
// Returns: void
//--------------------------------------------------------------------------
void decipher_AES(unsigned char *Plain_Data, unsigned char KeyIndex)
{
	unsigned char x, y;
	unsigned char temp_byte0, turn;

    Generate_Key(KeyIndex);       //expand the R_Key into 176 bytes
    turn = 9;
   
	  //initial addturnkey
	  for(x = 0; x < 16; x++)
	  {
		Plain_Data[ x]^=KeyGen[160 + x];
	  }

	  //10th turn without mixcols
	  inv_add_S_Box_and_shift(Plain_Data, turn);

	  for (turn = 8; turn >= 0; turn--){               // The compiler will throw a warning about this line of code- ignore it!
			for(x = 0; x < 16; x+= 4)
			{
				for(y = 0; y < 2; y++)
				{
					temp_byte0 = G_Multiply(G_Multiply(Plain_Data[x+y]^Plain_Data[x+y+2]));
					Plain_Data[x+y] ^= temp_byte0;     
					Plain_Data[x+y+2] ^= temp_byte0;     
				}
			}
			//mixcolums //////////
			mix_column(Plain_Data);	

			//addturnkey, inv_S_Box and shiftrows
			inv_add_S_Box_and_shift(Plain_Data, turn);
			
			if(turn == 0)
				break;
	  }
}


