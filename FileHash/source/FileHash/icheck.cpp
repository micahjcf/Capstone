#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <string>

using namespace std;

#include <dllMDSHA.h>
#include <dllMFA256.h>

char SHATestHashes[6][41] = {"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
							"86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8",
							"A9993E364706816ABA3E25717850C26C9CD0D89D",
							"32D10C7B8CF96570CA04CE37F2A19D84240D3A89",
							"34AA973CD4C4DAA4F61EEB2BDBAD27316534016F",
							"3466E0982BDC24C5E773EDE63B1C57A3EF16FAF9"};

char MD5TestHashes[6][33] = {"D41D8CD98F00B204E9800998ECF8427E",
							"0CC175B9C0F1B6A831C399E269772661",
							"900150983CD24FB0D6963F7D28E17F72",
							"C3FCD3D76192E4007DFB496CCA67E13B",
							"7707D6AE4E027C70EEA2A935C2296F21",
							"7C8FEC9C937FA3AF75F21C4223B0D8CF"};

char MFATestHashes[6][65] = {"FE826539936346024EF3D23ACA7F833C70752CF1ADCBE99E104C2B8F3923261C",
							"B62D44B9CCAA1AA82DC038C5422E6CFA31F64847627607B2619F4AED291A9C96",
							"76A9E0C76FCD438BD777264A57545568D6DD25ABF8B394308A09F0813FC58B3F",
							"4F9A77A43C0AC41F6FE5B6E4CE928ACD1F369588DE7B50E3389906CF78EB15E2",
							"66CB4F99A7ECD961EB8B7AFDA486C16A3E259605890FEAC688187E84D4CF2CB7"};

//****************************************************************
template <typename Type>
string ntoh(Type Number)
{
	string res = "";
	static char hex[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	BYTE c;

	for(int n = 0; n < sizeof(Number); n++)
	{
		c = (BYTE)(Number >> ((sizeof(Number)-n-1)*8));

		res += hex[ (c & 240) >> 4 ];
		res += hex[ c & 15 ];
	}

	return res;
}

//****************************************************************
int RunSHA1Test(int verbose)
{
	if(verbose)
		printf("\tRunning SHA1 test vectors!\n");

	SHA1State State;
	BYTE digest[ SHA1HashSize ];

	string hash_string = "";

	BYTE alphabet[] = "abcdefghijklmnopqrstuvwxyz";
	BYTE million[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	BYTE full_block[] = "Secure Hash Algo";

	UINT n, outcome = 0;

	//### NULL ###
	SHA1Init(&State);
	SHA1Result(&State, digest);

	for(n = 0; n < 20; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = NULL hash\n", SHATestHashes[0]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != SHATestHashes[0])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### 'a' ###
	hash_string = "";
	SHA1Init(&State);
	SHA1Update(&State, alphabet, 1);
	SHA1Result(&State, digest);

	for(n = 0; n < 20; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = \"a\"\n", SHATestHashes[1]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != SHATestHashes[1])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### 'abc' ###
	hash_string = "";
	SHA1Init(&State);
	SHA1Update(&State, alphabet, 3);
	SHA1Result(&State, digest);

	for(n = 0; n < 20; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = \"abc\"\n", SHATestHashes[2]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != SHATestHashes[2])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### (alphabet) ###
	hash_string = "";
	SHA1Init(&State);
	SHA1Update(&State, alphabet, 26);
	SHA1Result(&State, digest);

	for(n = 0; n < 20; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = (alphabet)\n", SHATestHashes[3]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != SHATestHashes[3])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### million ###
	hash_string = "";
	SHA1Init(&State);
	for(n = 0; n < 15625; n++)
		SHA1Update(&State, million, 64);
	SHA1Result(&State, digest);

	for(n = 0; n < 20; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = a * 1000000\n", SHATestHashes[4]);
		printf("%s\n", hash_string.c_str());
	}
	
	if(hash_string != SHATestHashes[4])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### full block ###
	hash_string = "";
	SHA1Init(&State);
	for(n = 0; n < 4; n++)
		SHA1Update(&State, full_block, 16);
	SHA1Result(&State, digest);

	for(n = 0; n < 20; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = \"Secure Hash Algo\" * 4\n", SHATestHashes[5]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != SHATestHashes[5])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	return outcome;
}

//****************************************************************
int RunMD5Test(int verbose)
{
	if(verbose)
		printf("\tRunning MD5 test vectors!\n");

	MD5State State;
	BYTE digest[ MD5HashSize ];

	string hash_string = "";

	BYTE alphabet[] = "abcdefghijklmnopqrstuvwxyz";
	BYTE full_block[] = "Message Digest 5";
	BYTE million[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

	UINT n, outcome = 0;

	//### NULL ###
	MD5Init(&State);
	MD5Result(&State, digest);

	for(n = 0; n < 16; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = NULL hash\n", MD5TestHashes[0]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != MD5TestHashes[0])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### 'a' ###
	hash_string = "";
	MD5Init(&State);
	MD5Update(&State, alphabet, 1);
	MD5Result(&State, digest);

	for(n = 0; n < 16; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = \"a\"\n", MD5TestHashes[1]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != MD5TestHashes[1])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### 'abc' ###
	hash_string = "";
	MD5Init(&State);
	MD5Update(&State, alphabet, 3);
	MD5Result(&State, digest);

	for(n = 0; n < 16; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = \"abc\"\n", MD5TestHashes[2]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != MD5TestHashes[2])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### (alphabet) ###
	hash_string = "";
	MD5Init(&State);
	MD5Update(&State, alphabet, 26);
	MD5Result(&State, digest);

	for(n = 0; n < 16; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = (alphabet)\n", MD5TestHashes[3]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != MD5TestHashes[3])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### million ###
	hash_string = "";
	MD5Init(&State);
	for(n = 0; n < 15625; n++)
		MD5Update(&State, million, 64);
	MD5Result(&State, digest);

	for(n = 0; n < 16; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = a * 1000000\n", MD5TestHashes[4]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != MD5TestHashes[4])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### full block ###
	hash_string = "";
	MD5Init(&State);
	for(n = 0; n < 4; n++)
		MD5Update(&State, full_block, 16);
	MD5Result(&State, digest);

	for(n = 0; n < 16; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = \"Message Digest 5\" * 4\n", MD5TestHashes[5]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != MD5TestHashes[5])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	return outcome;
}

//****************************************************************
int RunMFATest(int verbose)
{
	if(verbose)
		printf("\tRunning MFA-256 test vectors!\n");

	MFAState State;
	BYTE digest[ MFAHashSize ];

	string hash_string = "";

	BYTE alphabet[] = "abcdefghijklmnopqrstuvwxyz";
	BYTE full_block[] = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzab";
	BYTE million[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

	UINT n, outcome = 0;

	//### NULL ###
	MFAInit(&State);
	MFAResult(&State, digest);

	for(n = 0; n < 32; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = NULL hash\n", MFATestHashes[0]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != MFATestHashes[0])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### 'a' ###
	hash_string = "";
	MFAInit(&State);
	MFAUpdate(&State, alphabet, 1);
	MFAResult(&State, digest);

	for(n = 0; n < 32; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = \"a\" hash\n", MFATestHashes[1]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != MFATestHashes[1])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### (alphabet) ###
	hash_string = "";
	MFAInit(&State);
	MFAUpdate(&State, alphabet, 26);
	MFAResult(&State, digest);

	for(n = 0; n < 32; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = (alphabet)\n", MFATestHashes[2]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != MFATestHashes[2])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### full block ###
	hash_string = "";
	MFAInit(&State);
	MFAUpdate(&State, million, 64);
	MFAUpdate(&State, million, 16);
	MFAResult(&State, digest);

	for(n = 0; n < 32; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = a * 80\n", MFATestHashes[3]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != MFATestHashes[3])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	//### million ###
	hash_string = "";
	MFAInit(&State);
	for(n = 0; n < 15625; n++)
		MFAUpdate(&State, million, 64);
	MFAResult(&State, digest);

	for(n = 0; n < 32; n++)
		hash_string += ntoh(digest[n]);

	if(verbose)
	{
		printf("%s = a * 1000000\n", MFATestHashes[4]);
		printf("%s\n", hash_string.c_str());
	}

	if(hash_string != MFATestHashes[4])
	{
		if(verbose)
			printf("Test Failure!\n\n");
		outcome = 1;
	}
	else if (verbose)
		printf("Test Passed\n\n");

	return outcome;
}