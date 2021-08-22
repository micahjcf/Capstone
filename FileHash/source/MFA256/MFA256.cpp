#include <MFA256.h>

#define bitsize(x) (sizeof(x) << 3)
#define rotl(x, n) (((x) << (n)) | ((x) >> (bitsize(x) - (n))))

#define sigma0(x)	(x + (rotl(x, 7) ^ rotl(x, 22)))
#define sigma1(x)	(x ^ (rotl(x, 13) + rotl(x, 27)))
#define sigma2(x)	(x + rotl(x, 16))
#define sigma3(x)	(x ^ rotl(x, 3) ^ rotl(x, 17))

Word K[64] = {
	0x46E97E9A, 0x1BCE81B6, 0xBB8EFFB8, 0xE4A2353E,
	0xC07E77EB, 0xB326E7D7, 0xEF16CA66, 0x493D7A1F,
	0x76A8D32C, 0x66FE81D1, 0x5429A7BA, 0x78EEF40B,
	0xC69A78B0, 0xF2C7DEF2, 0xD09F33E8, 0x8EDC5D7A,
	0x8CF9EB54, 0xEEE27FAD, 0x67606050, 0x7F2DD66F,
	0x1751201E, 0x9A48010B, 0x9A2BEE62, 0x35C7B6A6,
	0xE7AF1E8E, 0x00F25B18, 0x5E9E0445, 0x9E8666B5,
	0x8E31E502, 0x5946572C, 0x4CCA2155, 0x7BB503BC,
	0xAD83A969, 0xA6D2EB0C, 0x749F44CB, 0x60574AA3,
	0x97B88D86, 0xEE21E31F, 0x059DF378, 0xB9EA645C,
	0x56727A7B, 0x50F9EA81, 0xC8B66202, 0x54FCEF49,
	0x657EA0F3, 0xDB99936C, 0x3B2687AC, 0x3141F7CA,
	0xE0825A6E, 0xAC89F129, 0xC9CAF1C8, 0x0D507859,
	0x28E068C2, 0x078AAFC9, 0xE0EA14D0, 0xF1631487,
	0x2DFBC84D, 0x4E73FAFA, 0x2455A0CA, 0xDA4F47DB,
	0xCCF6D828, 0x2108321A, 0x8CFD512F, 0x9CA7AB20
};

Word GetNextSquareFreeChar(Word* state)
{
	Word prev_zero(*state), temp, bits;

	do{
		++(*state);

		temp = *state;
		bits = 0;

		if(temp)
			do bits++; while(temp &= (temp-1));

	} while(bits & 1);

	return (*state) - prev_zero - 1;
}

void MFAInit(MFAState* State)
{
	State->ChainingVars[0] = 0xFE826539;
	State->ChainingVars[1] = 0x93634602;
	State->ChainingVars[2] = 0x4EF3D23A;
	State->ChainingVars[3] = 0xCA7F833C;
	State->ChainingVars[4] = 0x70752CF1;
	State->ChainingVars[5] = 0xADCBE99E;
	State->ChainingVars[6] = 0x104C2B8F;
	State->ChainingVars[7] = 0x3923261C;

	State->C_High =	0x6F2DEC53;
	State->C_Low =	0xA4523B59;

	State->MsgIndex = 0;

	State->Length_Low = 0;
	State->Length_High = 0;

	State->SequenceState = 0;
}

void MFACompressF(MFAState* State)
{
	Word A, B, C, D, E, F, G, H, t, W[70];
	unsigned int n;

	// Copy over M to W
	for(n = 0; n < 20; n++)
		W[n] = (State->MsgBlock[4*n] << 24) | (State->MsgBlock[4*n+1] << 16) |
			(State->MsgBlock[4*n+2] << 8) | State->MsgBlock[4*n+3];

	// C Injection
	W[20] = State->C_High;
	W[21] = State->C_Low;

	// Message Expansion part 1
	for(n = 22; n < 46; n++)
		W[n] = rotl(W[n-1], 7) + (W[n-5] ^ W[n-11] ^ W[n-16]) + rotl(W[n-22] + W[n-3], 27);

	// Message Expansion part 2
	for(n = 46; n < 70; n++)
		W[n] = rotl(W[n-1], 9) + (W[n-6] ^ W[n-16] ^ W[n-31]) + rotl(W[n-24] + W[n-2], 19);

	// C Collection
	State->C_High = W[68];
	State->C_Low = W[69];

	A = State->ChainingVars[0];
	B = State->ChainingVars[1];
	C = State->ChainingVars[2];
	D = State->ChainingVars[3];
	E = State->ChainingVars[4];
	F = State->ChainingVars[5];
	G = State->ChainingVars[6];
	H = State->ChainingVars[7];

	for(n = 0; n < 70; n++)
	{
		B += A + W[n];
		A = rotl(A, 3);
		C += K[ B & 63 ];
		D += sigma0(A);

		F += E + W[n];
		G += K[ W[n] & 63 ];
		H += sigma1(E);

		t = H;
		H = G;
		G = F;
		F = E;
		E = D;
		D = C;
		C = B;
		B = A;
		A = t;
	}

	State->ChainingVars[0] += A;
	State->ChainingVars[1] += B;
	State->ChainingVars[2] += C;
	State->ChainingVars[3] += D;
	State->ChainingVars[4] += E;
	State->ChainingVars[5] += F;
	State->ChainingVars[6] += G;
	State->ChainingVars[7] += H;
}

void MFACompressG(MFAState* State)
{
	Word A, B, C, D, E, F, G, H, t, W[70];
	unsigned int n;

	// Copy over M to W
	for(n = 0; n < 20; n++)
		W[n + 2] = (State->MsgBlock[4*n] << 24) | (State->MsgBlock[4*n+1] << 16) |
			(State->MsgBlock[4*n+2] << 8) | State->MsgBlock[4*n+3];

	// C Injection
	W[0] = State->C_High;
	W[1] = State->C_Low;

	// Message Expansion part 1
	for(n = 22; n < 46; n++)
		W[n] = rotl(W[n-1], 23) + (W[n-3] ^ W[n-7] ^ W[n-18]) + rotl(W[n-22] + W[n-2], 7);

	// Message Expansion part 2
	for(n = 46; n < 70; n++)
		W[n] = rotl(W[n-1], 7) + (W[n-6] ^ W[n-12] ^ W[n-21]) + rotl(W[n-24] + W[n-2], 27);

	// C Collection
	State->C_High = W[68];
	State->C_Low = W[69];

	A = State->ChainingVars[0];
	B = State->ChainingVars[1];
	C = State->ChainingVars[2];
	D = State->ChainingVars[3];
	E = State->ChainingVars[4];
	F = State->ChainingVars[5];
	G = State->ChainingVars[6];
	H = State->ChainingVars[7];

	for(n = 0; n < 70; n++)
	{
		B += A + W[n];
		C += K[ sigma2(A) & 63 ];
		D += A;

		F += E + W[n];
		G += K[ F & 63 ];
		H = rotl(H, 7) + E;
		E = ~E;

		t = H;
		H = G;
		G = F;
		F = E;
		E = D;
		D = C;
		C = B;
		B = A;
		A = t;
	}

	State->ChainingVars[0] += A;
	State->ChainingVars[1] += B;
	State->ChainingVars[2] += C;
	State->ChainingVars[3] += D;
	State->ChainingVars[4] += E;
	State->ChainingVars[5] += F;
	State->ChainingVars[6] += G;
	State->ChainingVars[7] += H;
}

void MFACompressH(MFAState* State)
{
	Word A, B, C, D, E, F, G, H, t, W[70];
	unsigned int n;

	// Copy over M to W
	for(n = 0; n < 20; n++)
		W[n + 1] = (State->MsgBlock[4*n] << 24) | (State->MsgBlock[4*n+1] << 16) |
			(State->MsgBlock[4*n+2] << 8) | State->MsgBlock[4*n+3];

	// C Injection
	W[0] = State->C_High;
	W[21] = State->C_Low;

	// Message Expansion part 1
	for(n = 22; n < 46; n++)
		W[n] = rotl(W[n-2], 29) + (W[n-4] ^ W[n-9] ^ W[n-15]) + rotl(W[n-22] + W[n-1], 5);

	// Message Expansion part 2
	for(n = 46; n < 70; n++)
		W[n] = rotl(W[n-24], 13) + (W[n-5] ^ W[n-10] ^ W[n-19]) + rotl(W[n-2] + W[n-1], 19);

	// C Collection
	State->C_High = W[68];
	State->C_Low = W[69];

	A = State->ChainingVars[0];
	B = State->ChainingVars[1];
	C = State->ChainingVars[2];
	D = State->ChainingVars[3];
	E = State->ChainingVars[4];
	F = State->ChainingVars[5];
	G = State->ChainingVars[6];
	H = State->ChainingVars[7];

	for(n = 0; n < 70; n++)
	{
		B = rotl(B, 9);
		D += B;

		F = rotl(F, 5);
		H += F;

		A += K[ n & 63 ] + W[n];
		C += sigma3(A);

		E += K[ D & 63 ] + W[n] + D;
		G += E;

		t = H;
		H = G;
		G = F;
		F = E;
		E = D;
		D = C;
		C = B;
		B = A;
		A = t;
	}

	State->ChainingVars[0] += A;
	State->ChainingVars[1] += B;
	State->ChainingVars[2] += C;
	State->ChainingVars[3] += D;
	State->ChainingVars[4] += E;
	State->ChainingVars[5] += F;
	State->ChainingVars[6] += G;
	State->ChainingVars[7] += H;
}

void MFAProcessBlock(MFAState* State)
{
	int next( GetNextSquareFreeChar(&State->SequenceState) );

	if(next == 0)
		MFACompressF(State);

	if(next == 1)
		MFACompressG(State);

	if(next == 2)
		MFACompressH(State);

	State->MsgIndex = 0;
}

void MFAUpdate(MFAState* State, unsigned char* M, unsigned int nLen)
{
	if(!nLen)
		return;

	if ((State->Length_Low + (nLen << 3)) < State->Length_Low)
		State->Length_High++;

	State->Length_Low += (nLen << 3);
	State->Length_High += (nLen >> 29);

	do {
		State->MsgBlock[ State->MsgIndex++ ] = *(M++);

		if(State->MsgIndex == 80)
			MFAProcessBlock(State);
	} while(--nLen);
}

void MFAResult(MFAState* State, unsigned char Hash[ MFAHashSize ])
{
	unsigned int n;
	Word t;

	if((State->Length_High | State->Length_Low) == 0)
	{
		for(int n = 0; n < 8; n++)
		{
			Hash[n*4  ] = (Byte)(State->ChainingVars[n] >> 24);
			Hash[n*4+1] = (Byte)(State->ChainingVars[n] >> 16);
			Hash[n*4+2] = (Byte)(State->ChainingVars[n] >> 8);
			Hash[n*4+3] = (Byte)State->ChainingVars[n];
		}

		return;
	}

	if(State->MsgIndex)
	{
		do {
			State->MsgBlock[ State->MsgIndex++ ] = 0;
		} while(State->MsgIndex != 80);

		MFAProcessBlock(State);
	}

	for(n = 0; n < 20; n++)
	{
		t = rotl(State->C_High, n) + State->C_Low;

		State->MsgBlock[n*4  ] = (Byte)(t >> 24);
		State->MsgBlock[n*4+1] = (Byte)(t >> 16);
		State->MsgBlock[n*4+2] = (Byte)(t >> 8);
		State->MsgBlock[n*4+3] = (Byte)t;
	}

	State->C_High = State->Length_High;
	State->C_Low = State->Length_Low;

	MFAProcessBlock(State);

	for(n = 0; n < 8; n++)
	{
		Hash[n*4  ] = (Byte)(State->ChainingVars[n] >> 24);
		Hash[n*4+1] = (Byte)(State->ChainingVars[n] >> 16);
		Hash[n*4+2] = (Byte)(State->ChainingVars[n] >> 8);
		Hash[n*4+3] = (Byte)State->ChainingVars[n];
	}
}
