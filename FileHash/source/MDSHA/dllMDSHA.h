#ifndef _MJCF_MDSHA_DLLINTERFACE_
#define _MJCF_MDSHA_DLLINTERFACE_

#ifdef MDSHA_EXPORTS
#define MDSHA_API __declspec(dllexport)
#else
#define MDSHA_API __declspec(dllimport)
#endif

#define MD5HashSize	16
#define SHA1HashSize 20

typedef struct _MD5State
{
	BYTE	MsgBlock[ 64 ];
	DWORD	Intermediate_Hash[ 4 ];
	DWORD	Length_Low;
	DWORD	Length_High;
} MD5State;

typedef struct _SHA1State
{
	BYTE	Message_Block[ 64 ];
	DWORD	Intermediate_Hash[ 5 ];
	DWORD	Length_Low;
	DWORD	Length_High;
} SHA1State;

void MDSHA_API MD5Init(MD5State* State);
void MDSHA_API MD5Update(MD5State* State, BYTE* inBuf, UINT nLen);
void MDSHA_API MD5Result(MD5State* State, BYTE digest[ MD5HashSize ]);

void MDSHA_API SHA1Init(SHA1State*);
void MDSHA_API SHA1Update(SHA1State*, BYTE*, UINT);
void MDSHA_API SHA1Result(SHA1State*, BYTE[ SHA1HashSize ]);

#endif
