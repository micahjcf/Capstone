typedef unsigned int	UINT;
typedef unsigned long	DWORD;
typedef unsigned char	BYTE;

#define bitsize(x) (sizeof(x) << 3)
#define rotl(x, n) (((x) << (n)) | ((x) >> (bitsize(x) - (n))))

#include <dllMDSHA.h>

// Local Function Prototyptes
void SHA1PadMessage(SHA1State*);
void SHA1ProcessMessageBlock(SHA1State*);

//****************************************************************
void MDSHA_API SHA1Init(SHA1State* State)
{
	State->Intermediate_Hash[0] = 0x67452301;
	State->Intermediate_Hash[1] = 0xEFCDAB89;
	State->Intermediate_Hash[2] = 0x98BADCFE;
	State->Intermediate_Hash[3] = 0x10325476;
	State->Intermediate_Hash[4] = 0xC3D2E1F0;

	State->Length_Low = 0;
	State->Length_High = 0;
}

//****************************************************************
void MDSHA_API SHA1Result(SHA1State* State, BYTE Message_Digest[ SHA1HashSize ])
{
	UINT i;

	SHA1PadMessage(State);

	for(i = 0; i < SHA1HashSize; ++i)
		Message_Digest[i] = (BYTE)(State->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) ));
}

//****************************************************************
void MDSHA_API SHA1Update(SHA1State* State, BYTE* message_array, UINT length)
{
	UINT shai = (UINT)((State->Length_Low >> 3) & 0x3F);

	if (((DWORD)(State->Length_Low + ((DWORD)length << 3))) < State->Length_Low)
		State->Length_High++;

	State->Length_Low += ((DWORD)length << 3);
	State->Length_High += ((DWORD)length >> 29);

	while(length--)
	{
		State->Message_Block[shai++] = (*(message_array++) & 0xFF);

		if(shai == 64)
		{
			shai = 0;
			SHA1ProcessMessageBlock(State);
		}
	}
}

//****************************************************************
void SHA1ProcessMessageBlock(SHA1State* State)
{
	UINT t;
	DWORD A, B, C, D, E, temp, W[80];

	// Initialize the first 16 words in W
	for(t = 0; t < 16; t++)
	{
		W[t] = State->Message_Block[t * 4] << 24;
		W[t] |= State->Message_Block[t * 4 + 1] << 16;
		W[t] |= State->Message_Block[t * 4 + 2] << 8;
		W[t] |= State->Message_Block[t * 4 + 3];
	}

	// Run message expansion
	for(t = 16; t < 80; t++)
		W[t] = rotl(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);

	A = State->Intermediate_Hash[0];
	B = State->Intermediate_Hash[1];
	C = State->Intermediate_Hash[2];
	D = State->Intermediate_Hash[3];
	E = State->Intermediate_Hash[4];

	// Round 1
	for(t = 0; t < 20; t++)
	{
		temp = rotl(A, 5) + ((B & C) | ((~B) & D)) + E + W[t] + 0x5A827999;
		E = D;
		D = C;
		C = rotl(B, 30);
		B = A;
		A = temp;
	}

	// Round 2
	for(t = 20; t < 40; t++)
	{
		temp = rotl(A, 5) + (B ^ C ^ D) + E + W[t] + 0x6ED9EBA1;
		E = D;
		D = C;
		C = rotl(B, 30);
		B = A;
		A = temp;
	}

	// Round 3
	for(t = 40; t < 60; t++)
	{
		temp = rotl(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[t] + 0x8F1BBCDC;
		E = D;
		D = C;
		C = rotl(B, 30);
		B = A;
		A = temp;
	}

	// Round 4
	for(t = 60; t < 80; t++)
	{
		temp = rotl(A, 5) + (B ^ C ^ D) + E + W[t] + 0xCA62C1D6;
		E = D;
		D = C;
		C = rotl(B, 30);
		B = A;
		A = temp;
	}

	State->Intermediate_Hash[0] += A;
	State->Intermediate_Hash[1] += B;
	State->Intermediate_Hash[2] += C;
	State->Intermediate_Hash[3] += D;
	State->Intermediate_Hash[4] += E;
}

//****************************************************************
void SHA1PadMessage(SHA1State* State)
{
	/*
	* Check to see if the current message block is too small to hold
	* the initial padding bits and length. If so, we will pad the
	* block, process it, and then continue padding into a second
	* block.
	*/

	UINT shai = (UINT)((State->Length_Low >> 3) & 0x3F);

	if(shai > 55)
	{
		State->Message_Block[shai++] = 0x80;

		while(shai < 64)
			State->Message_Block[shai++] = 0;

		SHA1ProcessMessageBlock(State);

		while(shai < 56)
			State->Message_Block[shai++] = 0;
	}
	else
	{
		State->Message_Block[shai++] = 0x80;

		while(shai < 56)
			State->Message_Block[shai++] = 0;
	}

	State->Message_Block[56] = (BYTE)(State->Length_High >> 24);
	State->Message_Block[57] = (BYTE)(State->Length_High >> 16);
	State->Message_Block[58] = (BYTE)(State->Length_High >> 8);
	State->Message_Block[59] = (BYTE)(State->Length_High);
	State->Message_Block[60] = (BYTE)(State->Length_Low >> 24);
	State->Message_Block[61] = (BYTE)(State->Length_Low >> 16);
	State->Message_Block[62] = (BYTE)(State->Length_Low >> 8);
	State->Message_Block[63] = (BYTE)(State->Length_Low);

	SHA1ProcessMessageBlock(State);
}
