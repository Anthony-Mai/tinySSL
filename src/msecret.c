/******************************************************************************
*
* Copyright © 2014 Anthony Mai Mai_Anthony@hotmail.com. All Rights Reserved.
*
* This software is written by Anthony Mai who retains full copyright of this
* work. As such any Copyright Notices contained in this code. are NOT to be
* removed or modified. If this package is used in a product, Anthony Mai
* should be given attribution as the author of the parts of the library used.
* This can be in the form of a textual message at program startup or in
* documentation (online or textual) provided with the package.
*
* This library is free for commercial and non-commercial use as long as the
* following conditions are aheared to. The following conditions apply to
* all code found in this distribution:
*
* 1. Redistributions of source code must retain the copyright notice, this
*    list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* 3. All advertising materials mentioning features or use of this software
*    must display the following acknowledgement:
*
*    "This product contains software written by Anthony Mai (Mai_Anthony@hotmail.com)
*     The original source code can obtained from such and such internet sites or by
*     contacting the author directly."
*
* 4. This software may or may not contain patented technology owned by a third party.
*    Obtaining a copy of this software, with or without explicit authorization from
*    the author, does NOT imply that applicable patents have been licensed. It is up
*    to you to make sure that utilization of this software package does not infringe
*    on any third party's patents or other intellectual proerty rights.
* 
* THIS SOFTWARE IS PROVIDED BY ANTHONY MAI "AS IS". ANY EXPRESS OR IMPLIED WARRANTIES,
* INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
* FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
* BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
* IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
* 
* The licence and distribution terms for any publically available version or derivative
* of this code cannot be changed.  i.e. this code cannot simply be copied and put under
* another distribution licence [including the GNU Public Licence.]
*
******************************************************************************/

/******************************************************************************
*
*  File Name:       msecret.c
*
*  Description:     Generate Master Secret from pre-master secret.
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         6/28/2014 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/
#include <string.h>
#include <stdint.h>

#include "msecret.h"

#include "cipher.h"

#include "ssl_int.h"
#include "hmac.h"


//#define MASTER_SECRET_TEST  // Define this for the Master Secret test.


#ifdef MASTER_SECRET_TEST

//The following test data were taken from this web site:
//  http://wp.netscape.com/eng/ssl3/traces/trc-clnt-ex.html#ClientKeyExchange1

uchar gPreMasterSecret[48] =
{
    0x03, 0x00, 0x43, 0xc0, 0x06, 0x15, 0xe4, 0x0a, 0xe7, 0xfa, 0xb0, 0x8f, 0x6c, 0x95, 0xd7, 0x6b,
    0xa6, 0x77, 0x30, 0x9a, 0xb8, 0x0d, 0x02, 0x54, 0xb9, 0x84, 0x21, 0x33, 0x0b, 0x9d, 0x46, 0x21,
    0xec, 0xc7, 0x9b, 0xd0, 0xd7, 0x6c, 0xe3, 0xb5, 0x3f, 0xf9, 0x64, 0x1b, 0xe0, 0xfe, 0x5b, 0x83
};

uchar gClientRandom[32] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x90, 0x06, 0x46, 0x69, 0x20, 0x81, 0x64, 0x08, 0xba, 0xb4, 0x3f, 0x9f, 0x81, 0xfa, 0x5b, 0x20
};

uchar gServerRandom[32] =
{
    0x34, 0x02, 0x87, 0x24, 0x8e, 0xea, 0xbd, 0xf7, 0xc2, 0x8c, 0xfc, 0xfe, 0x39, 0x54, 0x90, 0xbb,
    0x06, 0xfe, 0x48, 0xb4, 0xa2, 0x07, 0xfc, 0x9d, 0x2a, 0xd2, 0xd9, 0x2c, 0x84, 0x82, 0x58, 0xbe
};

uchar gMasterSecret[48] =
{
    0xf6, 0x63, 0x98, 0xc5, 0xc4, 0x84, 0xe0, 0xc4, 0xc1, 0xe7, 0x4b, 0x2d, 0xef, 0x62, 0x9c, 0xf9,
    0xfd, 0x49, 0x30, 0x07, 0xce, 0x6c, 0xb7, 0x00, 0xad, 0x00, 0x23, 0xa5, 0x0d, 0x2e, 0x40, 0xb2,
    0x88, 0x07, 0x4f, 0x19, 0xac, 0x52, 0xb6, 0x43, 0x61, 0x77, 0xd7, 0x87, 0xbb, 0x17, 0x9c, 0xc4
};


uchar gKeyBlock[112] =
{
    0x18, 0x2a, 0x75, 0x51, 0xf8, 0x9f, 0x5c, 0xf9, 0x5c, 0x90, 0x0d, 0x0d, 0x76, 0x2f, 0x1e, 0x9e,
    0x33, 0x70, 0x58, 0x28, 0xf9, 0x05, 0x03, 0x85, 0x5b, 0x9d, 0xac, 0x39, 0x63, 0xc9, 0xe6, 0x9c,
    0xd6, 0x4f, 0x8a, 0xe7, 0xc9, 0x66, 0xea, 0x2d, 0x48, 0xc0, 0x80, 0xa5, 0x4d, 0x4a, 0xf2, 0xdf,
    0x94, 0xd5, 0x5a, 0xb3, 0xa6, 0xbc, 0xd3, 0x7a, 0x00, 0x22, 0x2f, 0x63, 0x8e, 0xca, 0x51, 0xc6,
    0x64, 0x9b, 0x85, 0x9b, 0x32, 0x16, 0x00, 0x5c, 0xf2, 0x91, 0xb2, 0x40, 0x20, 0xfc, 0x61, 0x3b,
    0x59, 0x0e, 0x93, 0x93, 0x14, 0x6a, 0xc2, 0x79, 0xff, 0x41, 0xeb, 0x07, 0xc0, 0x48, 0x97, 0x2c,
    0x79, 0x35, 0xa5, 0x64, 0xeb, 0x42, 0xfa, 0x12, 0xd1, 0x81, 0x15, 0xe0, 0x10, 0xcf, 0xa0, 0x93
};

uchar gClientMac[16] =
{
    0x18, 0x2a, 0x75, 0x51, 0xf8, 0x9f, 0x5c, 0xf9, 0x5c, 0x90, 0x0d, 0x0d, 0x76, 0x2f, 0x1e, 0x9e
};

uchar gServerMac[16] =
{
    0x33, 0x70, 0x58, 0x28, 0xf9, 0x05, 0x03, 0x85, 0x5b, 0x9d, 0xac, 0x39, 0x63, 0xc9, 0xe6, 0x9c
};

uchar gClientKey[16] =
{
    0xd6, 0x4f, 0x8a, 0xe7, 0xc9, 0x66, 0xea, 0x2d, 0x48, 0xc0, 0x80, 0xa5, 0x4d, 0x4a, 0xf2, 0xdf
};

uchar gServerKey[16] =
{
    0x94, 0xd5, 0x5a, 0xb3, 0xa6, 0xbc, 0xd3, 0x7a, 0x00, 0x22, 0x2f, 0x63, 0x8e, 0xca, 0x51, 0xc6
};


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

int VerifyMasterSecretCode(SSL* pSSL);

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus

int VerifyMasterSecretCode(SSL* pSSL)
{
    uint    iRet = 0;

    pSSL->ePendingCipher = CIPHER_RSA_RC4_128_MD5;

    memcpy(pSSL->preMasterSecret, gPreMasterSecret, sizeof(gPreMasterSecret));
    memcpy(pSSL->clientRandom, gClientRandom, sizeof(gClientRandom));
    memcpy(pSSL->serverRandom, gServerRandom, sizeof(gServerRandom));

    CalcMasterSecret(
            pSSL->masterSecret,
            pSSL->preMasterSecret,
            pSSL->clientRandom,
            pSSL->serverRandom
            );

    iRet |= memcmp(pSSL->masterSecret, gMasterSecret, MASTER_SECRET_LEN);

    CalcKeysFromMaster(pSSL, ISCLIENT);
    CalcKeysFromMaster(pSSL, ISSERVER);

    iRet |= memcmp(pSSL->clientMacSecret, gClientMac, sizeof(gClientMac));
    iRet |= memcmp(pSSL->serverMacSecret, gServerMac, sizeof(gServerMac));
    iRet |= memcmp(pSSL->clientWriteKey,  gClientKey, sizeof(gClientKey));
    iRet |= memcmp(pSSL->serverWriteKey,  gServerKey, sizeof(gServerKey));

    return iRet;
}

#endif //MASTER_SECRET_TEST


/******************************************************************************
* Function:     CalcMasterSecret
*
* Description:  Calculate Master secret using SSL 3.0
*
* Returns:      None.
******************************************************************************/
void CalcMasterSecret
(
    uchar       theMasterSecret[MASTER_SECRET_LEN],
    const uchar preMasterSecret[PRE_MASTER_SECRET_LEN],
    const uchar pClientRandom[CLIENT_RANDOM_LEN],
    const uchar pServerRandom[SERVER_RANDOM_LEN]
)
{
    MD5     md5a, md5b;
    SHA     sha1;
    uchar   sha1Digest[SHA1_SIZE];
    const CIPHER* pMd5 = &(gpCipherSet->md5);
    const CIPHER* pSha = &(gpCipherSet->sha1);

    pMd5->Init(&md5a, pMd5->pIData);
    pMd5->Input(&md5a, preMasterSecret, PRE_MASTER_SECRET_LEN);

    md5b = md5a;
    pSha->Init(&sha1, pSha->pIData);
    pSha->Input(&sha1, (uchar*)"A", 1);
    pSha->Input(&sha1, preMasterSecret, PRE_MASTER_SECRET_LEN);
    pSha->Input(&sha1, pClientRandom, CLIENT_RANDOM_LEN);
    pSha->Input(&sha1, pServerRandom, SERVER_RANDOM_LEN);
    pSha->Digest(&sha1, sha1Digest);
    pMd5->Input(&md5b, sha1Digest, sizeof(sha1Digest));
    pMd5->Digest(&md5b, &(theMasterSecret[0]));

    md5b = md5a;
    pSha->Init(&sha1, pSha->pIData);
    pSha->Input(&sha1, (uchar*)"BB", 2);
    pSha->Input(&sha1, preMasterSecret, PRE_MASTER_SECRET_LEN);
    pSha->Input(&sha1, pClientRandom, CLIENT_RANDOM_LEN);
    pSha->Input(&sha1, pServerRandom, SERVER_RANDOM_LEN);
    pSha->Digest(&sha1, sha1Digest);
    pMd5->Input(&md5b, sha1Digest, sizeof(sha1Digest));
    pMd5->Digest(&md5b, &(theMasterSecret[MD5_SIZE]));

    md5b = md5a;
    pSha->Init(&sha1, pSha->pIData);
    pSha->Input(&sha1, (uchar*)"CCC", 3);
    pSha->Input(&sha1, preMasterSecret, PRE_MASTER_SECRET_LEN);
    pSha->Input(&sha1, pClientRandom, CLIENT_RANDOM_LEN);
    pSha->Input(&sha1, pServerRandom, SERVER_RANDOM_LEN);
    pSha->Digest(&sha1, sha1Digest);
    pMd5->Input(&md5b, sha1Digest, sizeof(sha1Digest));
    pMd5->Digest(&md5b, &(theMasterSecret[MD5_SIZE*2]));
}


/******************************************************************************
* Function:     CalcKeysFromMaster
*
* Description:  Calculate keys from master secret using SSL 3.0
*               This function MUST be called twice causing redundant calculation.
*               Called upon the change cipher spec messages, once for client
*               and another time for server. The part not expected to be changed
*               must be preserved.
*
* Returns:      None.
******************************************************************************/
void CalcKeysFromMaster
(
    struct SSL* pSSL,
    uint        bIsClient
)
{
    MD5     md5a, md5b;
    SHA     sha1;
    uchar       shaDigest[SHA1_SIZE];
    uchar       macSecret[SHA1_SIZE];
    uchar       writeKey[16];
    const CIPHER*   pMd5 = &(gpCipherSet->md5);
    const CIPHER*   pSha = &(gpCipherSet->sha1);

    //Preserve the part that is not expected to be changed yet.
    if (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher)
    if (bIsClient)
    {
        memcpy(macSecret, pSSL->serverMacSecret, sizeof(macSecret));
        memcpy(writeKey, pSSL->serverWriteKey, sizeof(writeKey));
    }
    else
    {
        memcpy(macSecret, pSSL->clientMacSecret, sizeof(macSecret));
        memcpy(writeKey, pSSL->clientWriteKey, sizeof(writeKey));
    }

    if ((CIPHER_RSA_RC4_40_MD5  == pSSL->ePendingCipher) ||
        (CIPHER_RSA_RC4_128_MD5 == pSSL->ePendingCipher) ||
        (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher) )
    {
        pMd5->Init(&md5a, pMd5->pIData);
        pMd5->Input(&md5a, pSSL->masterSecret, sizeof(pSSL->masterSecret));

        //We need to generate a total key block of 64 bytes. Each round of
        //MD5 generates 16 bytes. They are assigned to ClientWriteMacSecret,
        //ServerWriteMacSecret,ClientWriteKey,ServerWriteKey,ClientWriteIV,
        //ServerWriteIV, respectively. Each is 16 bytes except no WriteIV.

        if (bIsClient || (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher))
        {
        //First round of MD5 is assigned to ClientWriteMacSecret
        md5b = md5a;
        pSha->Init(&sha1, pSha->pIData);
        pSha->Input(&sha1, (uchar*)"A", 1);
        pSha->Input(&sha1, pSSL->masterSecret, sizeof(pSSL->masterSecret));
        pSha->Input(&sha1, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pSha->Input(&sha1, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pSha->Digest(&sha1, shaDigest);
        pMd5->Input(&md5b, shaDigest, sizeof(shaDigest));
        pMd5->Digest(&md5b, pSSL->clientMacSecret);
        }

        if (!bIsClient || (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher))
        {
        //Second round of MD5 is assigned to ServerWriteMacSecret
        md5b = md5a;
        pSha->Init(&sha1, pSha->pIData);
        pSha->Input(&sha1, (uchar*)"BB", 2);
        pSha->Input(&sha1, pSSL->masterSecret, sizeof(pSSL->masterSecret));
        pSha->Input(&sha1, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pSha->Input(&sha1, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pSha->Digest(&sha1, shaDigest);
        pMd5->Input(&md5b, shaDigest, sizeof(shaDigest));
        pMd5->Digest(&md5b, pSSL->serverMacSecret);
        }

        //Third round of MD5 is assigned to ClientWriteKey, or ServerWriteKey, too
        md5b = md5a;
        pSha->Init(&sha1, pSha->pIData);
        pSha->Input(&sha1, (uchar*)"CCC", 3);
        pSha->Input(&sha1, pSSL->masterSecret, sizeof(pSSL->masterSecret));
        pSha->Input(&sha1, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pSha->Input(&sha1, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pSha->Digest(&sha1, shaDigest);
        pMd5->Input(&md5b, shaDigest, sizeof(shaDigest));
    }
    if ((CIPHER_RSA_RC4_128_MD5 == pSSL->ePendingCipher) ||
        (CIPHER_RSA_RC4_128_SHA == pSSL->ePendingCipher))
    {
        if (bIsClient || (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher))
        {
        //Output of third round of MD5
        pMd5->Digest(&md5b, pSSL->clientWriteKey);
        }

        if (!bIsClient || (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher))
        {
        //Fourth round of MD5 is assigned to ServerWriteKey
        md5b = md5a;
        pSha->Init(&sha1, pSha->pIData);
        pSha->Input(&sha1, (uchar*)"DDDD", 4);
        pSha->Input(&sha1, pSSL->masterSecret, sizeof(pSSL->masterSecret));
        pSha->Input(&sha1, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pSha->Input(&sha1, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pSha->Digest(&sha1, shaDigest);
        pMd5->Input(&md5b, shaDigest, sizeof(shaDigest));
        pMd5->Digest(&md5b, pSSL->serverWriteKey);
        }

        if (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher)
        {
        //We need a Fifth round of MD5, as client and server MAC secret is each 20 bytes.
        md5b = md5a;
        pSha->Init(&sha1, pSha->pIData);
        pSha->Input(&sha1, (uchar*)"EEEEE", 5);
        pSha->Input(&sha1, pSSL->masterSecret, sizeof(pSSL->masterSecret));
        pSha->Input(&sha1, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pSha->Input(&sha1, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pSha->Digest(&sha1, shaDigest);
        pMd5->Input(&md5b, shaDigest, sizeof(shaDigest));

        memcpy(&(pSSL->clientMacSecret[16]), &(pSSL->serverMacSecret[0]), 4);
        memcpy(&(shaDigest[0]), &(pSSL->serverMacSecret[4]), 12);
        memcpy(&(shaDigest[12]), &(pSSL->clientWriteKey[0]), 8);
        memcpy(pSSL->serverMacSecret, shaDigest, 20);
        memcpy(&(pSSL->clientWriteKey[0]), &(pSSL->clientWriteKey[8]), 8);
        memcpy(&(pSSL->clientWriteKey[8]), &(pSSL->serverWriteKey[0]), 8);
        memcpy(&(pSSL->serverWriteKey[0]), &(pSSL->serverWriteKey[8]), 8);

        pMd5->Digest(&md5b, shaDigest);
        memcpy(&(pSSL->serverWriteKey[8]), shaDigest, 8);
        }
    }
    else if (CIPHER_RSA_RC4_40_MD5 == pSSL->ePendingCipher)
    {
        union {
            uchar   digest[MD5_SIZE];
            struct  {
                uchar   seedClientKey[5];   //40 bits
                uchar   seedServerKey[5];   //40 bits
                uchar   unUsed[6];
            }       keySeeds;
        }       theSeed;

        //Output of third round MD5 is 16 bytes, first 5 bytes used to seed generation
        //of ClientWriteKey, the next 5 bytes for seeding generation of ServerWriteKey.
        pMd5->Digest(&md5b, theSeed.digest);

        if (bIsClient)
        {
        pMd5->Init(&md5b, pMd5->pIData);
        pMd5->Input(&md5b, theSeed.keySeeds.seedClientKey, sizeof(theSeed.keySeeds.seedClientKey));
        pMd5->Input(&md5b, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pMd5->Input(&md5b, pSSL->serverRandom, sizeof(pSSL->serverRandom));

        //Output the ClientWriteKey, i.e., MD5 hash of the seed, clientRandom and ServerRandom.
        pMd5->Digest(&md5b, pSSL->clientWriteKey);
        }
        else
        {
        //Now generate the ServerWriteKey.
        pMd5->Init(&md5b, pMd5->pIData);
        pMd5->Input(&md5b, theSeed.keySeeds.seedServerKey, sizeof(theSeed.keySeeds.seedClientKey));
        pMd5->Input(&md5b, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pMd5->Input(&md5b, pSSL->clientRandom, sizeof(pSSL->clientRandom));

        //Output the ClientWriteKey, i.e., MD5 hash of the seed, clientRandom and ServerRandom.
        pMd5->Digest(&md5b, pSSL->serverWriteKey);
        }
    }
    else
    {
        // Unsupported Cipher Suite.
    }

    //Recover the part that is not expected to be changed yet.
    if (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher)
    if (bIsClient)
    {
        memcpy(pSSL->serverMacSecret, macSecret, sizeof(macSecret));
        memcpy(pSSL->serverWriteKey, writeKey, sizeof(writeKey));
    }
    else
    {
        memcpy(pSSL->clientMacSecret, macSecret, sizeof(macSecret));
        memcpy(pSSL->clientWriteKey, writeKey, sizeof(writeKey));
    }
}


/******************************************************************************
* Function:     CalcMasterSecret1
*
* Description:  Calculate Master secret using SSL 3.1 (TLS 1.0).
*
* Returns:      None.
******************************************************************************/
void CalcMasterSecret1
(
    uchar       theMasterSecret[MASTER_SECRET_LEN],
    const uchar preMasterSecret[PRE_MASTER_SECRET_LEN],
    const uchar pClientRandom[CLIENT_RANDOM_LEN],
    const uchar pServerRandom[SERVER_RANDOM_LEN]
)
{
    int         i;
    uchar       md5Block[BLOCK_LEN];
    uchar       shaBlock[BLOCK_LEN];
    const char* pLabel = "master secret";
    const int   nLSize = strlen(pLabel);
    VDATA       dataBlocks[6] = {
        {NULL,  0},
        {NULL,  0},
        {(const uchar*)pLabel, nLSize},
        {pClientRandom, CLIENT_RANDOM_LEN},
        {pServerRandom, SERVER_RANDOM_LEN},
        {NULL,  0}
        };
    HMAC        hMAC;

    memset(md5Block, 0, sizeof(md5Block));
    memset(shaBlock, 0, sizeof(shaBlock));

    dataBlocks[1].pData = NULL;
    dataBlocks[1].nSize = 0;

    dataBlocks[0].pData = preMasterSecret;
    dataBlocks[0].nSize = ((PRE_MASTER_SECRET_LEN+1)>>1);
    HMAC_InitMD5(&hMAC, md5Block, &(dataBlocks[0]));

    dataBlocks[0].pData = &(preMasterSecret[PRE_MASTER_SECRET_LEN>>1]);
    dataBlocks[0].nSize = ((PRE_MASTER_SECRET_LEN+1)>>1);
    HMAC_InitSHA1(&hMAC, shaBlock, &(dataBlocks[0]));


    //First calculate P_MD5. See http://www.ietf.org/rfc/rfc2246.txt and rfc4104.txt.

    //First calculate A(1), A(2), A(3) for P_MD5 and P_SHA1

    //Calculate A(1);
    HMAC_MD5 (&hMAC, &(md5Block[MD5_SIZE*0]), &(dataBlocks[2]));
    HMAC_SHA1(&hMAC, &(shaBlock[SHA1_SIZE*0]), &(dataBlocks[2]));

    //Calculate A(2);
    dataBlocks[0].pData = &(md5Block[MD5_SIZE*0]);
    dataBlocks[0].nSize = MD5_SIZE;
    HMAC_MD5 (&hMAC, &(md5Block[MD5_SIZE*1]), &(dataBlocks[0]));
    dataBlocks[0].pData = &(shaBlock[SHA1_SIZE*0]);
    dataBlocks[0].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMAC, &(shaBlock[SHA1_SIZE*1]), &(dataBlocks[0]));

    //Calculate A(3);
    dataBlocks[0].pData = &(md5Block[MD5_SIZE*1]);
    dataBlocks[0].nSize = MD5_SIZE;
    HMAC_MD5 (&hMAC, &(md5Block[MD5_SIZE*2]), &(dataBlocks[0]));
    dataBlocks[0].pData = &(shaBlock[SHA1_SIZE*1]);
    dataBlocks[0].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMAC, &(shaBlock[SHA1_SIZE*2]), &(dataBlocks[0]));

    //Calculate HMAC_MD5(1) and HMAC_SHA1(1)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*0]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMAC, &(md5Block[MD5_SIZE*0]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*0]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMAC, &(shaBlock[SHA1_SIZE*0]), &(dataBlocks[1]));

    //Calculate HMAC_MD5(2) and HMAC_SHA1(2)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*1]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMAC, &(md5Block[MD5_SIZE*1]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*1]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMAC, &(shaBlock[SHA1_SIZE*1]), &(dataBlocks[1]));

    //Calculate HMAC_MD5(3) and HMAC_SHA1(3)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*2]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMAC, &(md5Block[MD5_SIZE*2]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*2]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMAC, &(shaBlock[SHA1_SIZE*2]), &(dataBlocks[1]));

    //Finally calculate the Master Secret from P_MD5 and P_SHA1.
    for (i=0; i<MASTER_SECRET_LEN; i++)
    {
        theMasterSecret[i] = md5Block[i] ^ shaBlock[i];
    }
}


/******************************************************************************
* Function:     CalcKeysFromMaster1
*
* Description:  Calculate keys from master secret using SSL 3.1 (TLS 1.0).
*               This function may be called twice causing redundant calculation.
*               Called upon the change cipher spec messages, once for client
*               and another time for server.
*
* Returns:      None.
******************************************************************************/
void CalcKeysFromMaster1
(
    SSL*    pSSL,
    uint    bIsClient
)
{
    int          i, nMacSize = MAC_SECRET_LEN;
    uchar        md5Block[MD5_SIZE*5];
    uchar        shaBlock[SHA1_SIZE*4];
    const char*  pLabel = "key expansion";
    const int    nLSize = strlen(pLabel);
    const uchar* p1;
    const uchar* p2;
    VDATA       dataBlocks[6] = {
        {NULL,  0},
        {NULL,  0},
        {(const uchar*)pLabel, nLSize},
        {pSSL->serverRandom, SERVER_RANDOM_LEN},
        {pSSL->clientRandom, CLIENT_RANDOM_LEN},
        {NULL,  0}
        };
    HMAC        hMac;

    memset(md5Block, 0, sizeof(md5Block));
    memset(shaBlock, 0, sizeof(shaBlock));
    memcpy(md5Block, pSSL->masterSecret, (MASTER_SECRET_LEN+1)>>1);
    memcpy(shaBlock, &(pSSL->masterSecret[PRE_MASTER_SECRET_LEN>>1]), (PRE_MASTER_SECRET_LEN+1)>>1);

    memset(md5Block, 0, sizeof(md5Block));
    memset(shaBlock, 0, sizeof(shaBlock));

    dataBlocks[1].pData = NULL;
    dataBlocks[1].nSize = 0;

    dataBlocks[0].pData = &(pSSL->masterSecret[0]);
    dataBlocks[0].nSize = ((MASTER_SECRET_LEN+1)>>1);
    HMAC_InitMD5(&hMac, md5Block, &(dataBlocks[0]));

    dataBlocks[0].pData = &(pSSL->masterSecret[MASTER_SECRET_LEN>>1]);
    dataBlocks[0].nSize = ((MASTER_SECRET_LEN+1)>>1);
    HMAC_InitSHA1(&hMac, shaBlock, &(dataBlocks[0]));

    //First calculate P_MD5. See http://www.ietf.org/rfc/rfc2246.txt and rfc4104.txt.

    //Calculate A(1);
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*0]), &(dataBlocks[2]));
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*0]), &(dataBlocks[2]));

    //Calculate A(2);
    dataBlocks[0].pData = &(md5Block[MD5_SIZE*0]);
    dataBlocks[0].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*1]), &(dataBlocks[0]));
    dataBlocks[0].pData = &(shaBlock[SHA1_SIZE*0]);
    dataBlocks[0].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*1]), &(dataBlocks[0]));

    //Calculate A(3);
    dataBlocks[0].pData = &(md5Block[MD5_SIZE*1]);
    dataBlocks[0].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*2]), &(dataBlocks[0]));
    dataBlocks[0].pData = &(shaBlock[SHA1_SIZE*1]);
    dataBlocks[0].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*2]), &(dataBlocks[0]));

    //Calculate A(4);
    dataBlocks[0].pData = &(md5Block[MD5_SIZE*2]);
    dataBlocks[0].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*3]), &(dataBlocks[0]));
    dataBlocks[0].pData = &(shaBlock[SHA1_SIZE*2]);
    dataBlocks[0].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*3]), &(dataBlocks[0]));

    //Calculate A(5) for HMAC_MD5 only. To get a minimum 72 bytes keyblock
    if (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher)
    {
    dataBlocks[0].pData = &(md5Block[MD5_SIZE*3]);
    dataBlocks[0].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*4]), &(dataBlocks[0]));
    }

    //Now calculate HMAC_MD5 and HMAC_SHA1.

    //Calculate HMAC_MD5(1) and HMAC_SHA1(1)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*0]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*0]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*0]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*0]), &(dataBlocks[1]));

    //Calculate HMAC_MD5(2) and HMAC_SHA1(2)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*1]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*1]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*1]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*1]), &(dataBlocks[1]));

    //Calculate HMAC_MD5(3) and HMAC_SHA1(3)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*2]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*2]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*2]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*2]), &(dataBlocks[1]));

    //Calculate HMAC_MD5(4) and HMAC_SHA1(4)
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*3]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*3]), &(dataBlocks[1]));
    dataBlocks[1].pData = &(shaBlock[SHA1_SIZE*3]);
    dataBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMac, &(shaBlock[SHA1_SIZE*3]), &(dataBlocks[1]));

    //Calculate HMAC_MD5(5) only. To get a minimum 72 bytes keyblock
    if (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher)
    {
    dataBlocks[1].pData = &(md5Block[MD5_SIZE*4]);
    dataBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMac, &(md5Block[MD5_SIZE*4]), &(dataBlocks[1]));
    }

    //Finally calculate the key block from P_MD5 and P_SHA1.
    p1 = md5Block;
    p2 = shaBlock;

    nMacSize = MAC_SECRET_LEN;
    if (CIPHER_RSA_RC4_128_SHA  == pSSL->ePendingCipher)
    {
    nMacSize = SHA1_SIZE;
    }

    if (bIsClient)
    for (i=0; i<nMacSize; i++)
    {
        pSSL->clientMacSecret[i] = (*p1++) ^ (*p2++);
    }
    else
    {
        p1 += nMacSize; p2 += nMacSize;
    }

    if (bIsClient)
    {
        p1 += nMacSize; p2 += nMacSize;
    }
    else
    for (i=0; i<nMacSize; i++)
    {
        pSSL->serverMacSecret[i] = (*p1++) ^ (*p2++);
    }

    //Handle special case of 40 bits key. This is yet to be verified.
    if (CIPHER_RSA_RC4_40_MD5 == pSSL->ePendingCipher)
    {
        union {
            uchar   digest[MD5_SIZE];
            struct  {
                uchar   seedClientKey[5];
                uchar   seedServerKey[5];
                uchar   unUsed[6];
            }       keySeeds;
        }       theSeed;
        MD5 md5;
        const CIPHER* pMd5 = &(gpCipherSet->md5);

        //Output next 16 bytes of key block, first 5 bytes used to seed generation
        //of ClientWriteKey, the next 5 bytes for generation of ServerWriteKey.
        for (i=0; i<MD5_SIZE; i++)
        {
            theSeed.digest[i] = (*p1++) ^ (*p2++);
        }

        if (bIsClient)
        {
        pMd5->Init(&md5, pMd5->pIData);
        pMd5->Input(&md5, theSeed.keySeeds.seedClientKey, sizeof(theSeed.keySeeds.seedClientKey));
        pMd5->Input(&md5, pSSL->clientRandom, sizeof(pSSL->clientRandom));
        pMd5->Input(&md5, pSSL->serverRandom, sizeof(pSSL->serverRandom));

        //Output the ClientWriteKey, i.e., MD5 hash of the seed, clientRandom and ServerRandom.
        pMd5->Digest(&md5, pSSL->clientWriteKey);
        }
        else
        {
        //Now generate the ServerWriteKey.
        pMd5->Init(&md5, pMd5->pIData);
        pMd5->Input(&md5, theSeed.keySeeds.seedServerKey, sizeof(theSeed.keySeeds.seedClientKey));
        pMd5->Input(&md5, pSSL->serverRandom, sizeof(pSSL->serverRandom));
        pMd5->Input(&md5, pSSL->clientRandom, sizeof(pSSL->clientRandom));

        //Output the ClientWriteKey, i.e., MD5 hash of the seed, clientRandom and ServerRandom.
        pMd5->Digest(&md5, pSSL->serverWriteKey);
        }

        //We are done here for the 40 bits key special case.
        return;
    }

    if (bIsClient)
    for (i=0; i<WRITE_KEY_LEN; i++)
    {
        pSSL->clientWriteKey[i] = (*p1++) ^ (*p2++);
    }
    else
    {
        p1 += WRITE_KEY_LEN; p2 += WRITE_KEY_LEN;
    }

    if (bIsClient)
    {
        p1 += WRITE_KEY_LEN; p2 += WRITE_KEY_LEN;
    }
    else
    for (i=0; i<WRITE_KEY_LEN; i++)
    {
        pSSL->serverWriteKey[i] = (*p1++) ^ (*p2++);
    }
}
