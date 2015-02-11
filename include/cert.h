#ifndef _CERT_H_INCLUDED_6_27_2014_
#define _CERT_H_INCLUDED_6_27_2014_


#define CERT_TEST     //Define to test CERT implementation against test suite


//Certificate Status
//The bits are as following:
//  bit 2:  Verified bit. Certificate signature checked.
//  bit 4-3:
//        0 0   Status unknown. Or self signed byt not root.
//        0 1   Bad. The certificate is verified to be bad
//        1 0   Good. The certificate is authenticated.
//        1 1   Pending. The status is pending further verification.
//  bit 3:  BAD bit. The certificate is BAD. Bit 4 must be 0.
//  bit 4:  OK bit. The certificate is OK. Bit 3 must be 0.
//  bit 5:  Revoked bit. The certificate is on the CRL list.
//  bit 6:  Self-signed bit. The certificate is self signing.
//  bit 7:  Root bit.   The certificate is a root certificate.
//  bit 8:  Expired bit. The certificate has expired.
//  bit 9:  None-exist bit: The certificate does not exist.
typedef enum
{
    CS_UNKNOWN      = 0,
    CS_VERIFIED     = 0x04,
    CS_BAD          = 0x08,
    CS_OK           = 0x10,
    CS_PENDING      = 0x18,
    CS_REVOKED      = 0x20,
    CS_SELF         = 0x40,
    CS_ROOT         = 0x80,
    CS_EXPIRED      = 0x0100,
    CS_NONE_EXIST   = 0x0200
} CERT_STATUS;

#define     SIGNATURE_OK                    0
#define     SIGNATURE_INVALID               -1  //Signature is verified to be invalid.
#define     SIGNATURE_WRONG_CERTIFICATE     1   //The issuer certificate is not the correct one.
#define     SIGNATURE_INVALID_CERTIFICATE   2   //The issuer certificate is correct but not validated.

//Forward declaration
struct CERT;
struct CIPHERSET;
typedef struct CERT      CERT;
typedef struct CERT*     HCERT;
typedef struct CIPHERSET CIPHERSET;


#define CERT_SIZE(p) ((((uint)(((uchar*)p)[2]))<<8) + ((uint)(((uchar*)p)[3])) + 4)


//Function pointer type definitions
typedef void* (*FMalloc)(size_t nSize);     //App provided memory allocate function.
typedef void  (*FFree)(void* pMemBlock);    //App provided memory free function.
typedef uint (* ENUMCERT_FUNC) (struct CERT* pCert, void* pUuserData);


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

void StartCerts(FMalloc pMallocFunc, FFree pFreeFunc, const CIPHERSET* pCipherSet);
CERT* CreateCert(CERT_STATUS eStatus, uint nUnixTime);
void CleanupCerts(CERT** ppMidCerts);
uint ParseCert(CERT* pCert, const uchar* pMsg, uint nMsgSize);
void DestroyCert(CERT* pCert);
CERT* InsertCert(CERT* pCert, CERT** ppMidCerts);
CERT* DeleteCert(CERT* pCert, CERT** ppMidCerts);
CERT_STATUS AuthenticateCert(CERT* pCert, CERT** ppMidCerts);
uint EnumCerts(ENUMCERT_FUNC pEnumFunc, void* pUserData);
uint GetPubKeyLen(const CERT* pCert);
uint EncryptByCert(const CERT* pCert, uchar* pData, uint nDataSize);
uint GetPubKey(const CERT* pCert, uchar* pKey);
uint GetPubExp(const CERT* pCert);
const char*  GetCertName(const CERT* pCert);
uint GetUniqueName(const CERT* pCert, uchar* pBuffer, uint nBuffSize);
uint ParseX509ID(struct X509NAME* pName, const uchar* pMsg, uint nMsgSize);

#ifdef CERT_TEST
uint DoCertTest();
#endif //CERT_TEST

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _CERT_H_INCLUDED_6_27_2014_
