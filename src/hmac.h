#ifndef _HMAC_H_INCLUDED_6_28_2014_
#define _HMAC_H_INCLUDED_6_28_2014_


#define OPAD_CHAR   0x5C
#define IPAD_CHAR   0x36

#define BLOCK_LEN   64  //Block length for HMAC calculation


typedef struct VDATA
{
    const uchar*    pData;
    uint            nSize;
} VDATA;

typedef struct HMAC {
    CTX     md5a, md5b;
    CTX     sha1a, sha1b;
} HMAC;

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

void HMAC_InitMD5 (HMAC* pHMAC, uchar hashBlock[BLOCK_LEN], const VDATA* pKeyBlock);
void HMAC_InitSHA1(HMAC* pHMAC, uchar hashBlock[BLOCK_LEN], const VDATA* pKeyBlock);
void HMAC_MD5 (HMAC* pHMAC, uchar md5Hash[MD5_SIZE], const VDATA* pDataBlocks);
void HMAC_SHA1(HMAC* pHMAC, uchar shaHash[SHA1_SIZE], const VDATA* pDataBlocks);

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _HMAC_H_INCLUDED_6_28_2014_
