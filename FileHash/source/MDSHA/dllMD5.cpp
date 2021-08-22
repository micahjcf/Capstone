typedef unsigned int	UINT;
typedef unsigned long	DWORD;
typedef unsigned char	BYTE;

#define bitsize(x) (sizeof(x) << 3)
#define rotl(x, n) (((x) << (n)) | ((x) >> (bitsize(x) - (n))))

#include <dllMDSHA.h>

/* Padding */
static BYTE MD5_PADDING[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* MD5_F, MD5_G and MD5_H are basic MD5 functions: selection, majority, parity */
#define MD5_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))

/* MD5_FF, MD5_GG, MD5_HH, and MD5_II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define MD5_FF(A, B, C, D, x, s, ac) {(A) += MD5_F ((B), (C), (D)) + (x) + (DWORD)(ac); (A) = rotl ((A), (s)); (A) += (B); }
#define MD5_GG(A, B, C, D, x, s, ac) {(A) += MD5_G ((B), (C), (D)) + (x) + (DWORD)(ac); (A) = rotl ((A), (s)); (A) += (B); }
#define MD5_HH(A, B, C, D, x, s, ac) {(A) += MD5_H ((B), (C), (D)) + (x) + (DWORD)(ac); (A) = rotl ((A), (s)); (A) += (B); }
#define MD5_II(A, B, C, D, x, s, ac) {(A) += MD5_I ((B), (C), (D)) + (x) + (DWORD)(ac); (A) = rotl ((A), (s)); (A) += (B); }

/* Constants for transformation */
#define MD5_S11 7  /* Round 1 */
#define MD5_S12 12
#define MD5_S13 17
#define MD5_S14 22
#define MD5_S21 5  /* Round 2 */
#define MD5_S22 9
#define MD5_S23 14
#define MD5_S24 20
#define MD5_S31 4  /* Round 3 */
#define MD5_S32 11
#define MD5_S33 16
#define MD5_S34 23
#define MD5_S41 6  /* Round 4 */
#define MD5_S42 10
#define MD5_S43 15
#define MD5_S44 21

//****************************************************************
void MDSHA_API MD5Init(MD5State* State)
{
	State->Intermediate_Hash[0] = (DWORD)0x67452301;
	State->Intermediate_Hash[1] = (DWORD)0xefcdab89;
	State->Intermediate_Hash[2] = (DWORD)0x98badcfe;
	State->Intermediate_Hash[3] = (DWORD)0x10325476;

	State->Length_Low = 0;
	State->Length_High = 0;
}

//****************************************************************
/* Compression function, takes in a block and updates the intermediate hash*/
static void MD5_Transform(DWORD *Intermediate_Hash, DWORD *M)
{
	DWORD A = Intermediate_Hash[0];
	DWORD B = Intermediate_Hash[1];
	DWORD C = Intermediate_Hash[2];
	DWORD D = Intermediate_Hash[3];

	MD5_FF ( A, B, C, D, M[ 0], MD5_S11, (DWORD) 0xd76aa478); /* 1 */
	MD5_FF ( D, A, B, C, M[ 1], MD5_S12, (DWORD) 0xe8c7b756); /* 2 */
	MD5_FF ( C, D, A, B, M[ 2], MD5_S13, (DWORD) 0x242070db); /* 3 */
	MD5_FF ( B, C, D, A, M[ 3], MD5_S14, (DWORD) 0xc1bdceee); /* 4 */
	MD5_FF ( A, B, C, D, M[ 4], MD5_S11, (DWORD) 0xf57c0faf); /* 5 */
	MD5_FF ( D, A, B, C, M[ 5], MD5_S12, (DWORD) 0x4787c62a); /* 6 */
	MD5_FF ( C, D, A, B, M[ 6], MD5_S13, (DWORD) 0xa8304613); /* 7 */
	MD5_FF ( B, C, D, A, M[ 7], MD5_S14, (DWORD) 0xfd469501); /* 8 */
	MD5_FF ( A, B, C, D, M[ 8], MD5_S11, (DWORD) 0x698098d8); /* 9 */
	MD5_FF ( D, A, B, C, M[ 9], MD5_S12, (DWORD) 0x8b44f7af); /* 10 */
	MD5_FF ( C, D, A, B, M[10], MD5_S13, (DWORD) 0xffff5bb1); /* 11 */
	MD5_FF ( B, C, D, A, M[11], MD5_S14, (DWORD) 0x895cd7be); /* 12 */
	MD5_FF ( A, B, C, D, M[12], MD5_S11, (DWORD) 0x6b901122); /* 13 */
	MD5_FF ( D, A, B, C, M[13], MD5_S12, (DWORD) 0xfd987193); /* 14 */
	MD5_FF ( C, D, A, B, M[14], MD5_S13, (DWORD) 0xa679438e); /* 15 */
	MD5_FF ( B, C, D, A, M[15], MD5_S14, (DWORD) 0x49b40821); /* 16 */

	MD5_GG ( A, B, C, D, M[ 1], MD5_S21, (DWORD) 0xf61e2562); /* 17 */
	MD5_GG ( D, A, B, C, M[ 6], MD5_S22, (DWORD) 0xc040b340); /* 18 */
	MD5_GG ( C, D, A, B, M[11], MD5_S23, (DWORD) 0x265e5a51); /* 19 */
	MD5_GG ( B, C, D, A, M[ 0], MD5_S24, (DWORD) 0xe9b6c7aa); /* 20 */
	MD5_GG ( A, B, C, D, M[ 5], MD5_S21, (DWORD) 0xd62f105d); /* 21 */
	MD5_GG ( D, A, B, C, M[10], MD5_S22, (DWORD) 0x02441453); /* 22 */
	MD5_GG ( C, D, A, B, M[15], MD5_S23, (DWORD) 0xd8a1e681); /* 23 */
	MD5_GG ( B, C, D, A, M[ 4], MD5_S24, (DWORD) 0xe7d3fbc8); /* 24 */
	MD5_GG ( A, B, C, D, M[ 9], MD5_S21, (DWORD) 0x21e1cde6); /* 25 */
	MD5_GG ( D, A, B, C, M[14], MD5_S22, (DWORD) 0xc33707d6); /* 26 */
	MD5_GG ( C, D, A, B, M[ 3], MD5_S23, (DWORD) 0xf4d50d87); /* 27 */
	MD5_GG ( B, C, D, A, M[ 8], MD5_S24, (DWORD) 0x455a14ed); /* 28 */
	MD5_GG ( A, B, C, D, M[13], MD5_S21, (DWORD) 0xa9e3e905); /* 29 */
	MD5_GG ( D, A, B, C, M[ 2], MD5_S22, (DWORD) 0xfcefa3f8); /* 30 */
	MD5_GG ( C, D, A, B, M[ 7], MD5_S23, (DWORD) 0x676f02d9); /* 31 */
	MD5_GG ( B, C, D, A, M[12], MD5_S24, (DWORD) 0x8d2a4c8a); /* 32 */

	MD5_HH ( A, B, C, D, M[ 5], MD5_S31, (DWORD) 0xfffa3942); /* 33 */
	MD5_HH ( D, A, B, C, M[ 8], MD5_S32, (DWORD) 0x8771f681); /* 34 */
	MD5_HH ( C, D, A, B, M[11], MD5_S33, (DWORD) 0x6d9d6122); /* 35 */
	MD5_HH ( B, C, D, A, M[14], MD5_S34, (DWORD) 0xfde5380c); /* 36 */
	MD5_HH ( A, B, C, D, M[ 1], MD5_S31, (DWORD) 0xa4beea44); /* 37 */
	MD5_HH ( D, A, B, C, M[ 4], MD5_S32, (DWORD) 0x4bdecfa9); /* 38 */
	MD5_HH ( C, D, A, B, M[ 7], MD5_S33, (DWORD) 0xf6bb4b60); /* 39 */
	MD5_HH ( B, C, D, A, M[10], MD5_S34, (DWORD) 0xbebfbc70); /* 40 */
	MD5_HH ( A, B, C, D, M[13], MD5_S31, (DWORD) 0x289b7ec6); /* 41 */
	MD5_HH ( D, A, B, C, M[ 0], MD5_S32, (DWORD) 0xeaa127fa); /* 42 */
	MD5_HH ( C, D, A, B, M[ 3], MD5_S33, (DWORD) 0xd4ef3085); /* 43 */
	MD5_HH ( B, C, D, A, M[ 6], MD5_S34, (DWORD) 0x04881d05); /* 44 */
	MD5_HH ( A, B, C, D, M[ 9], MD5_S31, (DWORD) 0xd9d4d039); /* 45 */
	MD5_HH ( D, A, B, C, M[12], MD5_S32, (DWORD) 0xe6db99e5); /* 46 */
	MD5_HH ( C, D, A, B, M[15], MD5_S33, (DWORD) 0x1fa27cf8); /* 47 */
	MD5_HH ( B, C, D, A, M[ 2], MD5_S34, (DWORD) 0xc4ac5665); /* 48 */

	MD5_II ( A, B, C, D, M[ 0], MD5_S41, (DWORD) 0xf4292244); /* 49 */
	MD5_II ( D, A, B, C, M[ 7], MD5_S42, (DWORD) 0x432aff97); /* 50 */
	MD5_II ( C, D, A, B, M[14], MD5_S43, (DWORD) 0xab9423a7); /* 51 */
	MD5_II ( B, C, D, A, M[ 5], MD5_S44, (DWORD) 0xfc93a039); /* 52 */
	MD5_II ( A, B, C, D, M[12], MD5_S41, (DWORD) 0x655b59c3); /* 53 */
	MD5_II ( D, A, B, C, M[ 3], MD5_S42, (DWORD) 0x8f0ccc92); /* 54 */
	MD5_II ( C, D, A, B, M[10], MD5_S43, (DWORD) 0xffeff47d); /* 55 */
	MD5_II ( B, C, D, A, M[ 1], MD5_S44, (DWORD) 0x85845dd1); /* 56 */
	MD5_II ( A, B, C, D, M[ 8], MD5_S41, (DWORD) 0x6fa87e4f); /* 57 */
	MD5_II ( D, A, B, C, M[15], MD5_S42, (DWORD) 0xfe2ce6e0); /* 58 */
	MD5_II ( C, D, A, B, M[ 6], MD5_S43, (DWORD) 0xa3014314); /* 59 */
	MD5_II ( B, C, D, A, M[13], MD5_S44, (DWORD) 0x4e0811a1); /* 60 */
	MD5_II ( A, B, C, D, M[ 4], MD5_S41, (DWORD) 0xf7537e82); /* 61 */
	MD5_II ( D, A, B, C, M[11], MD5_S42, (DWORD) 0xbd3af235); /* 62 */
	MD5_II ( C, D, A, B, M[ 2], MD5_S43, (DWORD) 0x2ad7d2bb); /* 63 */
	MD5_II ( B, C, D, A, M[ 9], MD5_S44, (DWORD) 0xeb86d391); /* 64 */

	Intermediate_Hash[0] += A;
	Intermediate_Hash[1] += B;
	Intermediate_Hash[2] += C;
	Intermediate_Hash[3] += D;
}

//****************************************************************
void MDSHA_API MD5Update(MD5State* State, BYTE* M, UINT nLen)
{
	if(!nLen)
		return;

	DWORD M_Transform[16];
	UINT i = 0, ii = 0, mdi;

	/* Compute number of bytes mod 64 */
	mdi = (UINT)((State->Length_Low >> 3) & 0x3F);

	// Update number of bits
	if((State->Length_Low + ((DWORD)nLen << 3)) < State->Length_Low)
		State->Length_High++;

	State->Length_Low += ((DWORD)nLen << 3);
	State->Length_High += ((DWORD)nLen >> 29);

	while(nLen--)
	{
		/* Add new character, increment mdi */
		State->MsgBlock[mdi++] = *M++;

		/* Transform if necessary */
		if(mdi == 0x40)
		{
			for(i = 0, ii = 0; i < 16; i++, ii += 4)
				M_Transform[i] = (((DWORD)State->MsgBlock[ii+3]) << 24) |
					(((DWORD)State->MsgBlock[ii+2]) << 16) |
					(((DWORD)State->MsgBlock[ii+1]) << 8) |
					((DWORD)State->MsgBlock[ii]);

			MD5_Transform(State->Intermediate_Hash, M_Transform);
			mdi = 0;
		}
	}
}

//****************************************************************
void MDSHA_API MD5Result(MD5State* State, BYTE digest[ MD5HashSize ])
{
	DWORD LastBlock[16];
	UINT i = 0, ii = 0, padLen = 0, mdi;

	/* Save number of bits */
	LastBlock[14] = State->Length_Low;
	LastBlock[15] = State->Length_High;

	/* Compute number of bytes mod 64 */
	mdi = (int)((State->Length_Low >> 3) & 0x3F);

	/* Pad out to 56 mod 64 */
	padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);

	MD5Update(State, MD5_PADDING, padLen);

	/* Append length in bits and transform */
	for(i = 0, ii = 0; i < 14; i++, ii += 4)
		LastBlock[i] = (((DWORD)State->MsgBlock[ii+3]) << 24) |
			(((DWORD)State->MsgBlock[ii+2]) << 16) |
			(((DWORD)State->MsgBlock[ii+1]) <<  8) |
			((DWORD)State->MsgBlock[ii]);

	MD5_Transform(State->Intermediate_Hash, LastBlock);

	/* Store Intermediate_Hashfer in digest */
	for(i = 0, ii = 0; i < 4; i++, ii += 4)
	{
		digest[ii]   = (BYTE)( State->Intermediate_Hash[i]        & 0xFF);
		digest[ii+1] = (BYTE)((State->Intermediate_Hash[i] >>  8) & 0xFF);
		digest[ii+2] = (BYTE)((State->Intermediate_Hash[i] >> 16) & 0xFF);
		digest[ii+3] = (BYTE)((State->Intermediate_Hash[i] >> 24) & 0xFF);
	}
}
