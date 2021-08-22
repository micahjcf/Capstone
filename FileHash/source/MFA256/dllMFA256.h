#ifndef _MJCF_MFA256_DLLINTERFACE_
#define _MJCF_MFA256_DLLINTERFACE_

#ifdef MFA256_EXPORTS
#define MFA256_API __declspec(dllexport)
#else
#define MFA256_API __declspec(dllimport)
#endif

typedef unsigned long	Word;
typedef unsigned char	Byte;

#define MFAHashSize 32

typedef struct _MFAState
{
	Byte	MsgBlock[ 80 ];
	Word	ChainingVars[ 8 ];
	Word	C_High;
	Word	C_Low;
	Word	Length_High;
	Word	Length_Low;
	Word	SequenceState;
	Word	MsgIndex;
} MFAState;

void MFA256_API MFAInit(MFAState* State);
void MFA256_API MFAUpdate(MFAState* State, unsigned char* M, unsigned int nLen);
void MFA256_API MFAResult(MFAState* State, unsigned char Hash[ MFAHashSize ]);

#endif