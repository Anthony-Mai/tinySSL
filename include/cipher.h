#ifndef _CIPHER_H_INCLUDED_6_28_2014_
#define _CIPHER_H_INCLUDED_6_28_2014_


typedef enum {
    CIPHER_NONE,
    CIPHER_CUSTOM,
    CIPHER_RC4,
    CIPHER_MD5,
    CIPHER_SHA1,
    CIPHER_SHA256,
    CIPHER_RSA
} eCipher;


//Forward declarations

//Cipher context
struct CTX;
typedef struct CTX  CTX;

struct CDAT;
typedef struct CDAT  CDAT;


typedef void (*fInit)(CTX* pCtx, const CDAT* pData);
typedef void (*fInput)(CTX* pCtx, const uchar* pData, uint nSize);
typedef void (*fDigest)(CTX* pCtx, uchar pDigest[]);
typedef void (*fHash)(const uchar* pData, uint nSize, uchar pDigest[]);

typedef void (*fCode)(CTX* pCtx, uchar* pData, uint nSize);


typedef struct CIPHER
{
    uint    eCipher;//Cipher type
    uint    cSize;  //Context size
    uint    dSize;  //Digest size
    const struct CDAT* pIData;

    fInit   Init;
    union {
    fInput  Input;
    fCode   Code;
    };
    fDigest Digest;
    fHash   Hash;
} CIPHER;


typedef struct CIPHERSET {
    CIPHER  md5;
    CIPHER  sha1;
    CIPHER  sha256;
} CIPHERSET;


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

extern CIPHERSET gCipherSet;

const CIPHERSET* InitCiphers(CIPHERSET* pCipherSet, void* pUserData);

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _CIPHER_H_INCLUDED_6_28_2014_
