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
*  File Name:       serverMsg.c
*
*  Description:     SSL/TLS server messages.
*
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         6/28/2014 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "serverMsg.h"
#include "clientMsg.h"
#include "ssl_int.h"
#include "msecret.h"

#include "cert.h"
#include "BN.h"
#include "cipher.h"

#define DONE    1


static uint CreateCertificateRequestHelper(HCERT hCert, void* pUserData);
static uint CreateCertificateMsg(SSL* pSSL, uchar* pMsgBuff, uint nBuffSize);
uint CreateCertificateRequestMsg(SSL* pSSL, uchar* pMsgBuff, uint nBuffSize);
uint CreateServerHelloDoneMsg(SSL* pSSL, uchar* pMsgBuff, uint nBuffSize);
static void CalculateVerifySignature(SSL* pSSL, uchar* pSignature, uint nKeyLen);


uint CreateServerHelloMsg
(
    SSL*    pSSL,
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uint    i, nLen = 0;
    uchar*  pMsg = pMsgBuff;
    uchar*  pHashData;
    uint    nHashSize;

    pSSL->nTemp2 = 0; //No client certificate request by default.

    //Generate a ServerRandom
    for (i=0; i<sizeof(pSSL->serverRandom); )
    {   
        uint   nRand = gfRandom();
        *((uint*)&(pSSL->serverRandom[i])) = nRand;
        i += sizeof(uint);
    }
    pSSL->serverRandom[0] = (uchar)((pSSL->nCurrentTime)>>24);
    pSSL->serverRandom[1] = (uchar)((pSSL->nCurrentTime)>>16);
    pSSL->serverRandom[2] = (uchar)((pSSL->nCurrentTime)>>8 );
    pSSL->serverRandom[3] = (uchar)((pSSL->nCurrentTime)>>0 );

    //See if we need to generate a new Session ID, or reuse previous one.
    if (pSSL->nSessionIDLen == 0)
    {
        //This is a new connection session. Create a SessionID.
        pSSL->nSessionIDLen = sizeof(pSSL->sessionID);
        for (i=0; i<sizeof(pSSL->sessionID); )
        {   
            uint   nRand = gfRandom();
            *((uint*)&(pSSL->sessionID[i])) = nRand;
            i += sizeof(uint);
        }
        pSSL->sessionID[0] = 0x00;
        pSSL->sessionID[1] = 0x00;

        //We will send server certificate next.
        pSSL->eState = SSLSTATE_SERVER_CERTIFICATE;
    }
    else
    {
        //Resuming an existing connection session.
        //We will directly send ChangeCipherSpec and ServerFinish.
        pSSL->eState = SSLSTATE_SERVER_FINISH1;
    }

    //Now fill in the Server Hello Message
    *pMsg++ = CONTENT_HANDSHAKE;
    *pMsg++ = pSSL->preMasterSecret[0]; //SSL_VERSION_MAJOR;
    *pMsg++ = (SSL_VERSION_MINOR<pSSL->preMasterSecret[1])?SSL_VERSION_MINOR:pSSL->preMasterSecret[1];
    *pMsg++ = 0x00;     //These two bytes are content size
    *pMsg++ = 0x00;     //We will come back to fill them.

    //The content to be hashed in handshake hash starts here.
    pHashData = pMsg;

    *pMsg++ = MSG_SERVER_HELLO;
    *pMsg++ = 0x00;     //These three bytes are Message Size
    *pMsg++ = 0x00;
    *pMsg++ = 0x46;

    //First two bytes of SSL version.
    *pMsg++ = SSL_VERSION_MAJOR;
    *pMsg++ = SSL_VERSION_MINOR;

    //Then a fixed 32 bytes Server Random.
    memcpy(pMsg, pSSL->serverRandom, sizeof(pSSL->serverRandom));
    pMsg += sizeof(pSSL->serverRandom);

    //Then the Session ID length and the Session ID.
    *pMsg++ = (uchar) pSSL->nSessionIDLen;
    memcpy(pMsg, &(pSSL->sessionID[sizeof(pSSL->sessionID) - pSSL->nSessionIDLen]), pSSL->nSessionIDLen);
    pMsg += pSSL->nSessionIDLen;

    //Set PendingCipherSuite
    *pMsg++ = (uchar)(pSSL->ePendingCipher>>8);
    *pMsg++ = (uchar)(pSSL->ePendingCipher>>0);

    //Set Compression
    *pMsg++ = 0x00;

    //Go hack to correct Server Hello Message Size
    pHashData[3] = (uchar)(pMsg - pHashData - 4);

    nHashSize = (pMsg - pHashData);

    //Hash the handshake content of just ServerHello
    DigestMsg(pSSL, pHashData, nHashSize);

    if (SSLSTATE_SERVER_CERTIFICATE == pSSL->eState)
    {
        //Need to generate Server Certificate and Server Hello Done Message.
        pMsg += CreateCertificateMsg(pSSL, pMsg, nBuffSize - (pMsg - pMsgBuff));

        if (pSSL->pTemp != NULL) //If the server requests client certificate.
        {
            pSSL->pTemp = NULL; //Clean up things a bit.
            pMsg += CreateCertificateRequestMsg(pSSL, pMsg, nBuffSize - (pMsg - pMsgBuff));
            pSSL->eState = SSLSTATE_SERVER_CERTREQUEST;
        }
        else
        {
            pSSL->eState = SSLSTATE_SERVER_HELLO_DONE;
        }

        pMsg += CreateServerHelloDoneMsg(pSSL, pMsg, nBuffSize - (pMsg - pMsgBuff));

        if (pSSL->eState == SSLSTATE_SERVER_CERTREQUEST)
        {
            pSSL->eState = SSLSTATE_CERTIFICATE_REQUEST;
        }
        else
        {
            //Wait for ClientKeyExchange next.
            pSSL->eState = SSLSTATE_CLIENT_KEYEXCHANGE;
        }
    }

    if (pSSL->eServerCipher != CIPHER_NOTSET)
    {
        //If there is an existing cipher then we need to encrypt the message
        uint   nMacSize = 0;

        pMsg += nMacSize = EncryptWithMAC(
            pSSL,
            ISSERVER,   //We are server
            CONTENT_HANDSHAKE,
            pHashData,
            nHashSize
            );

        nHashSize += nMacSize;
    }

    //Moved here from a previous spot.
    nHashSize = (pMsg - pHashData);

    //Now go back to fill in the Handshake Content Size.
    pHashData[-2] = (uchar)(nHashSize>>8);
    pHashData[-1] = (uchar)(nHashSize>>0);

    nLen = (pMsg - pMsgBuff);

    return nLen;
}


/******************************************************************************
* Function:     CreateHelloRequestMsg
*
* Description:  Create a server hello request message, to prompt the client to
*               re-start a handshake session.
*
* Returns:      Bytes of message constructed.
******************************************************************************/
uint CreateHelloRequestMsg
(
    SSL*    pSSL,
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uint    nLen = 0;
    uchar*  pMsg = pMsgBuff;
    uchar*  pHashData;
    uint    nHashSize;


    //Now fill in the Hello Request message
    *pMsg++ = CONTENT_HANDSHAKE;
    *pMsg++ = SSL_VERSION_MAJOR;
    *pMsg++ = (SSL_VERSION_MINOR<pSSL->preMasterSecret[1])?SSL_VERSION_MINOR:pSSL->preMasterSecret[1];
    *pMsg++ = 0x00;     //These two bytes are content size
    *pMsg++ = 0x04;     //We will come back to fill them.

    //The content to be hashed in handshake hash starts here.
    pHashData = pMsg;

    *pMsg++ = MSG_HELLO_REQUEST;
    *pMsg++ = 0x00;     //These three bytes are Message Size
    *pMsg++ = 0x00;     //The Hello request message is an empty message
    *pMsg++ = 0x00;

    //Go hack to correct Server Hello Message Size
    nHashSize = (pMsg - pHashData);

    //Hash the handshake content of just ServerHello
    DigestMsg(pSSL, pHashData, nHashSize);

    if (pSSL->eServerCipher != CIPHER_NOTSET)
    {
        //If there is an existing cipher then we need to encrypt the message
        uint   nMacSize = 0;

        pMsg += nMacSize = EncryptWithMAC(
            pSSL,
            ISSERVER,   //We are server
            CONTENT_HANDSHAKE,
            pHashData,
            nHashSize
            );

        nHashSize += nMacSize;
    }

    //Go hack to fill in the content size.
    pHashData[-2] = (uchar)(nHashSize>>8);
    pHashData[-1] = (uchar)(nHashSize>>0);

    nLen = (pMsg - pMsgBuff);

    return nLen;
}


/******************************************************************************
* Function:     CreateCertificateMsg 
*
* Description:  Create the server certificate message.
*
* Returns:      Bytes of message constructed.
******************************************************************************/
uint CreateCertificateMsg
(
    SSL*    pSSL,
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uint    nLen = 0;
    uchar*  pMsg = pMsgBuff;
    uchar*  pHashData;
    uint    nHashSize;
    const CERTKEY_INFO* pCertKey = pSSL->pCertKey;
    const CERTKEY_INFO* pPrev = pCertKey;

    //The content to be hashed in handshake hash starts here.
    pHashData = pMsg;

    //The very first byte of course is MSG_CERTIFICATE
    *pMsg++ = MSG_CERTIFICATE;

    //First let's figure out how many certificates to be included in the message
    nLen = 3;
    for (;;)
    {
        nLen += CERT_SIZE(pCertKey->pCertificate);
        nLen += 3; //3 bytes for the length
        if (pCertKey->nKeyLengthBits > 0)
        {
            //This is the last one as nKeyLengthBits is non-zero.
            break;
        }
        else
        {
            pPrev = pCertKey;
            pCertKey = pCertKey->pNext;
        }
    }

    //Now having the total length we can start construct the certificate message
    *pMsg++ = (uchar)(nLen>>16);
    *pMsg++ = (uchar)(nLen>>8 );
    *pMsg++ = (uchar)(nLen>>0 );

    nLen -= 3;
    //Total certificate size.
    *pMsg++ = (uchar)(nLen>>16);
    *pMsg++ = (uchar)(nLen>>8 );
    *pMsg++ = (uchar)(nLen>>0 );

    //Now for each certificate. We do it in reverse order.
    for (;;)
    {
        nLen = CERT_SIZE(pCertKey->pCertificate);

        //This one certificate size.
        *pMsg++ = (uchar)(nLen>>16);
        *pMsg++ = (uchar)(nLen>>8 );
        *pMsg++ = (uchar)(nLen>>0 );

        //The certificate itself
        memcpy(pMsg, pCertKey->pCertificate, nLen);
        pMsg += nLen;

        if (pPrev == pCertKey)
        {
            //The very first one is the last one to be put into message.
            break;
        }
        else
        {
            pCertKey = pPrev;
            pPrev = pCertKey->pPrev;
            if (pPrev == NULL)
            {
                pPrev = pCertKey;
            }
        }
    }

    nHashSize = (pMsg - pHashData);

    //Hash the handshake content of just ServerHello
    DigestMsg(pSSL, pHashData, nHashSize);

    return (nLen = pMsg - pMsgBuff);
}


/******************************************************************************
* Function:     CreateCertificateRequestHelper
*
* Description:  Helper function for creating a certificate request message. We
*               enumerate our root certificate depository and construct a list
*               of unique names to create the certificate request message.
*
* Returns:      DONE (TRUE) means we are done, don't enumerate more. FALSE means continue.
******************************************************************************/
uint CreateCertificateRequestHelper
(
    HCERT   hCert,
    void*   pUserData
)
{
    CERT_STATUS eStatus;
    uint    nLen;
    SSL*    pSSL = (SSL*)pUserData;
    uchar*  pMsgBuff = pSSL->pTemp;
    uchar*  pMsg;

    if (hCert == NULL) return DONE;

    eStatus = AuthenticateCert(hCert, NULL);

    if (eStatus != (CS_ROOT|CS_SELF|CS_OK|CS_VERIFIED)) return DONE;

    nLen = 0;

    pMsg = pMsgBuff;
    *pMsg++ = (uchar)(nLen>>8);
    *pMsg++ = (uchar)(nLen>>0);

    pSSL->pTemp  += 2;
    pSSL->nTemp1 += 2;
    pSSL->nTemp2 -= 2;

    //Construct a X509 Identity
    nLen = GetUniqueName(hCert, pMsg, pSSL->nTemp2);

    pMsg = pMsgBuff;
    *pMsg++ = (uchar)(nLen>>8);
    *pMsg++ = (uchar)(nLen>>0);

    pSSL->pTemp  += nLen;
    pSSL->nTemp1 += nLen;
    pSSL->nTemp2 -= nLen;

    return !DONE;
}


/******************************************************************************
* Function:     CreateCertificateRequestMsg
*
* Description:  Create a certificate request message.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint CreateCertificateRequestMsg
(
    SSL*    pSSL,
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uint    nLen = 0;
    uchar*  pMsg = pMsgBuff;
    uchar*  pHashData;
    uint    nHashSize;

    //The content to be hashed in handshake hash starts here.
    pHashData = pMsg;    

    *pMsg++ = MSG_CERTIFICATE_REQUEST;

    //We will come back to fill in the correct numbers later
    nLen = 0;
    //nLen = sizeof(gCAName);
    nLen += 7;
    *pMsg++ = (uchar)(nLen>>16);
    *pMsg++ = (uchar)(nLen>>8 );
    *pMsg++ = (uchar)(nLen>>0 );

    *pMsg++ = 0x02;
    *pMsg++ = 0x01;
    *pMsg++ = 0x02;

    nLen -= 5;
    //Total certificate authority name size.
    *pMsg++ = (uchar)(nLen>>8 );
    *pMsg++ = (uchar)(nLen>>0 );

    nLen -= 2;

    {
        pSSL->pTemp  = pMsg;
        pSSL->nTemp1 = 0;
        pSSL->nTemp2 = nBuffSize - (pMsg-pMsgBuff);

        //Construct the CA list from root certificates.
        EnumCerts(CreateCertificateRequestHelper, (void*)pSSL);
        nLen = pSSL->pTemp - pMsg;

        nLen += 5;
        pMsg -= 8;

        //We now come back to fill in the correct size numbers.
        *pMsg++ = (uchar)(nLen>>16);
        *pMsg++ = (uchar)(nLen>>8 );
        *pMsg++ = (uchar)(nLen>>0 );

        *pMsg++ = 0x02;
        *pMsg++ = 0x01;
        *pMsg++ = 0x02;

        nLen -= 5;
        //Total certificate authority name size.
        *pMsg++ = (uchar)(nLen>>8 );
        *pMsg++ = (uchar)(nLen>>0 );

        pMsg += nLen;
    }

    nHashSize = (pMsg - pHashData);

    //Hash the handshake content of just ServerHello
    DigestMsg(pSSL, pHashData, nHashSize);

    pSSL->nTemp2 = MSG_CERTIFICATE_REQUEST; //This flags that we requested client certificate

    return (nLen = pMsg - pMsgBuff);
}


/******************************************************************************
* Function:     CreateServerHelloDoneMsg
*
* Description:  Create the server hello done message.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint CreateServerHelloDoneMsg
(
    SSL*    pSSL,
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uchar*  pMsg = pMsgBuff;
    uchar*  pHashData;
    uint    nHashSize;

//    *pMsg++ = CONTENT_HANDSHAKE;
//    *pMsg++ = SSL_VERSION_MAJOR;
//    *pMsg++ = SSL_VERSION_MINOR;
//    *pMsg++ = 0x00;     //These two bytes are content size
//    *pMsg++ = 0x04;     //We will come back to fill them.

    //The content to be hashed in handshake hash starts here.
    pHashData = pMsg;

    *pMsg++ = MSG_SERVER_HELLO_DONE;

    //The message size is 0
    *pMsg++ = 0x00;
    *pMsg++ = 0x00;
    *pMsg++ = 0x00;

    nHashSize = (pMsg - pHashData);

    //Hash the handshake content of just ServerHello
    DigestMsg(pSSL, pHashData, nHashSize);

    return (pMsg - pMsgBuff);
}


/******************************************************************************
* Function:     ParseClientKeyExchange
*
* Description:  Parse the client key exchange message.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseClientKeyExchange
(
    SSL*            pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uint   nMsgLen = 0, nKeyLen = 0;
    uint   nParsed = 0;
    uchar   msgBuff[256];   //Max 2048 bits RSA key
    const CERTKEY_INFO* pCertKey = pSSL->pCertKey;

    //Find the last that contains pointer to the public and private key.
    while (pCertKey->nKeyLengthBits == 0)
    {
        pCertKey = pCertKey->pNext;
    }

    nKeyLen = pCertKey->nKeyLengthBits >> 3;

    if (nKeyLen == nMsgSize)
    {
        //We are OK here. We are doing SSL 3.0. So copy the message in
        memcpy(msgBuff, pMsg, nMsgSize);
    }
    else if ((nKeyLen+2) == nMsgSize)
    {
        uint nLen2 = 0;

        //There are 2 extra bytes. We are probably doing SSL 3.1 or TLS 1.0.
        //The extra 2 bytes is the key length.
        nLen2   = (uint)*pMsg++;
        nLen2 <<= 8;
        nLen2  += (uint)*pMsg++;

        if (nLen2 == nKeyLen)
        {
            //We are OK. So copy over the message
            memcpy(msgBuff, pMsg, nKeyLen);
        }
        else
        {
            //We need to bail here as the key size and message size does not match
            pSSL->eState = SSLSTATE_ABORT;

            return nMsgSize;
        }
    }
    else
    {
        //We need to bail here as the key size and message size does not match
        pSSL->eState = SSLSTATE_ABORT;

        return nMsgSize;
    }

    BN_Decrypt(
        msgBuff,
        pCertKey->pPublicKey,
        pCertKey->pPrivateKey,
        nKeyLen
        );

    assert(0x00 == msgBuff[0]);
    assert(0x02 == msgBuff[1]);
    assert(0x00 == msgBuff[nKeyLen - sizeof(pSSL->preMasterSecret)-1]);

    memcpy(pSSL->preMasterSecret, &(msgBuff[nKeyLen - sizeof(pSSL->preMasterSecret)]), sizeof(pSSL->preMasterSecret));

    assert(SSL_VERSION_MAJOR == pSSL->preMasterSecret[0]);
    //assert(SSL_VERSION_MINOR == pSSL->preMasterSecret[1]);

    pSSL->eState = SSLSTATE_CLIENT_FINISH1;

    //Since we have everything needed we need to immediately calculate the MasterSecret
    if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
    {
        CalcMasterSecret(
            pSSL->masterSecret,
            pSSL->preMasterSecret,
            pSSL->clientRandom,
            pSSL->serverRandom
            );
    }
    else
    {
        CalcMasterSecret1(
            pSSL->masterSecret,
            pSSL->preMasterSecret,
            pSSL->clientRandom,
            pSSL->serverRandom
            );
    }

    return nMsgSize;
}


/******************************************************************************
* Function:     CalculateVerifySignature
*
* Description:  Calculate the expected certificate verify signature, unencrypted
*
* Returns:      None.
******************************************************************************/
void CalculateVerifySignature
(
    SSL*    pSSL,
    uchar*  pSignature,
    uint    nKeyLen
)
{
    uchar*  pMd5Digest;
    uchar*  pSha1Digest;
    EBLOCK  u;
//    union {
//        uchar       encryptBlock[256];  //Max RSA key is 2048 bits = 256 bytes
//        struct {
//            MD5         md5Hash;
//            SHA         sha1Hash;
//            uchar   md5Digest[MD5_SIZE];
//            uchar   sha1Digest[SHA1_SIZE];
//        };
//    }   u;

    pSha1Digest = &(pSignature[nKeyLen]);
    pSha1Digest -= SHA1_SIZE;
    pMd5Digest  = pSha1Digest - MD5_SIZE;

    //First copy the MD5 and SHA1 hash context for usage.
    DigestInit2(pSSL, &u);

    if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
    {
    //Calculate the inner MD5 and SHA1 hash
    DigestMsg2(&u, pSSL->masterSecret, sizeof(pSSL->masterSecret));

    DigestPad2(&u, PAD1);

    DigestOut2(&u);

    //Then calculate the outer MD5 and SHA1 hash
    DigestInit1(&u);

    DigestMsg2(&u, pSSL->masterSecret, sizeof(pSSL->masterSecret));

    DigestPad2(&u, PAD2);

    DigestBlock(&u);

    DigestOut2(&u);
    }
    else
    {
    //For SSL 3.1
    DigestOut2(&u);
    }

    //Important: Copy the SHA1 digest first!!!
    memcpy(pSha1Digest, u.sha1Digest, SHA1_SIZE);
    memcpy(pMd5Digest,  u.md5Digest,  MD5_SIZE);

    memset(pSignature, 0xFF, nKeyLen - (MD5_SIZE+SHA1_SIZE));
    pSignature[0]  = 0x00;
    pSignature[1]  = 0x01;
    pMd5Digest[-1] = 0x00;
}


/******************************************************************************
* Function:     ParseCertificateVerify
*
* Description:  Parse the certificate verify message.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseCertificateVerify
(
    SSL*            pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uint    nParsed = 0;
    uint    nSize;
    uint    nCopy;
    struct TBSCERTIFICATE* pCert = NULL;
    uchar   signature[256];
    uchar   tmpMsg[256]; //MAX signature block size for 2048 bits RSA key

    // First 2 bytes tells us the certificate verify signature size.
    nSize  = *pMsg++;
    nSize<<= 8;
    nSize += *pMsg++;
    nParsed += 2;

    nCopy = nSize;
    //assert(nCopy <= sizeof(tmpMsg));
    if (nCopy > sizeof(tmpMsg))
    {
        //Should never happen.
        nCopy = sizeof(tmpMsg);
    }

    memcpy(tmpMsg, pMsg, nCopy);
    pMsg += nSize;
    nParsed += nSize;

    EncryptByCert(pSSL->pServerCert, tmpMsg, nSize);
    //assert(nParsed == nMsgSize);

    CalculateVerifySignature(pSSL, signature, nSize);

    //Verify the signature.
    if (0 == memcmp(signature, tmpMsg, nSize))
    {
        //No error. Signature matches.
        pSSL->nTemp2 = 0;
    }
    else
    {
        //Signature does NOT verify.
        //The value either still remains at that value or we explicitly set it.
        //pSSL->nTemp2 at MSG_CERTIFICATE_REQUEST signals client certificate failed.
        pSSL->nTemp2 = MSG_CERTIFICATE_REQUEST;
    }

    return nParsed;
}


/******************************************************************************
* Function:     ParseClientChangeCipherSpec
*
* Description:  Parse the client change cipher spec message. After this point
*               all messages are encrypted.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseClientChangeCipherSpec
(
    SSL*                pSSL,
    const uchar*    pMsg,
    uint           nMsgSize
)
{
    //Verify the message is correct.
    assert(nMsgSize == 1);
    assert((*pMsg)  == 0x01);

    //The MasterSecret should have been generated so far. We now calculate keys.

    if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
    {
        CalcKeysFromMaster(pSSL, ISCLIENT);
    }
    else
    {
        CalcKeysFromMaster1(pSSL, ISCLIENT);
    }

    //From now on any thing from the client is encrypted.
    pSSL->eClientCipher = pSSL->ePendingCipher;

    //Initialize the client write cipher.
    if ((CIPHER_RSA_RC4_40_MD5  == pSSL->eClientCipher) ||
        (CIPHER_RSA_RC4_128_MD5 == pSSL->eClientCipher) )
    {
        RC4Init(
            &(pSSL->clientCipher),
            pSSL->clientWriteKey,
            sizeof(pSSL->clientWriteKey)
            );
    }
    else
    {
        //Unsupported cipher.
        assert(0);
    }

    //Reset the server write sequence number.
    pSSL->clientSequenceL = 0;
    pSSL->clientSequenceH = 0;

    return nMsgSize;
}


/******************************************************************************
* Function:     VerifyClientMAC
*
* Description:  Verify the client message MAC.
*
* Returns:      ZERO for no error, non-zero indicates error.
******************************************************************************/
uint VerifyClientMAC
(
    SSL*                pSSL,
    uchar           cMsgType,   //Content Type. e.g., CONTENT_HANDSHAKE
    const uchar*    pMsg,
    uint*          pSize
)
{
    uint   nMacSize, nMsgSize;
    uchar   digest[SHA1_SIZE]; //MAX(SHA1_SIZE, MD5_SIZE)

    switch (pSSL->eClientCipher)
    {
    case CIPHER_RSA_RC4_40_MD5:
    case CIPHER_RSA_RC4_128_MD5:
        nMacSize = MD5_SIZE;
        break;
    case CIPHER_RSA_RC4_128_SHA:
        nMacSize = SHA1_SIZE;
        break;
    default:
        //Unsupported cipher. Let's assume MAC size same as MD5.
        assert(0);
        nMacSize = 0;
        break;
    }

    nMsgSize = (*pSize) - nMacSize;

    nMacSize = CalculateMAC(
        pSSL,
        ISCLIENT,   //This message came from client
        digest,
        cMsgType,
        pMsg,
        nMsgSize
        );

    assert(nMacSize == ((*pSize)-nMsgSize));

    *pSize = nMsgSize;

    return memcmp(&(pMsg[nMsgSize]), digest, nMacSize);
}


/******************************************************************************
* Function:     CreateServerChangeCipherMsg
*
* Description:  Create the server change cipher spec message
*
* Returns:      Number of bytes of constructed.message.
******************************************************************************/
uint CreateServerChangeCipherMsg
(
    HSSL        pSSL,
    uchar*  pMsgBuff,
    uint   nBuffSize
)
{
    uint   nLen;
    uchar*  pMsg = pMsgBuff;
    uchar*  pHashData;
    uint   nHashSize;

    *pMsg++ = CONTENT_CHANGECIPHERSPEC;
    *pMsg++ = pSSL->preMasterSecret[0]; //SSL_VERSION_MAJOR;
    *pMsg++ = (SSL_VERSION_MINOR<pSSL->preMasterSecret[1])?SSL_VERSION_MINOR:pSSL->preMasterSecret[1];

    //The Message Body is 1 byte: That byte is 0x01.
    *pMsg++ = 0x00;
    *pMsg++ = 0x01; //The message length

    pHashData = pMsg;
    *pMsg++ = 0x01; //The message body


    nHashSize = (uint)(pMsg - pHashData);

    if (pSSL->eServerCipher != CIPHER_NOTSET)
    {
        //If there is an existing cipher then we need to encrypt the message
        uint   nMacSize = 0;

        pMsg += nMacSize = EncryptWithMAC(
            pSSL,
            ISSERVER,   //We are server
            CONTENT_CHANGECIPHERSPEC,
            pHashData,
            nHashSize
            );

        nHashSize += nMacSize;
    }

    //Go hack to fill in the content size.
    pHashData[-2] = (uchar)(nHashSize>>8);
    pHashData[-1] = (uchar)(nHashSize>>0);

    nLen = pMsg - pMsgBuff;

    //It is also time to calculate MasterSecret from PreMasterSecret.
    //Derive encryption keys from MasterSecret, and initialize cipher.

    //The MasterSecret is generated upon the Client Key Exchange Message
    if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
    {
        CalcKeysFromMaster(pSSL, ISSERVER);
    }
    else
    {
        CalcKeysFromMaster1(pSSL, ISSERVER);
    }

    //From now on any thing from the server is encrypted.
    pSSL->eServerCipher = pSSL->ePendingCipher;

    //Initialize the server write cipher.
    if ((CIPHER_RSA_RC4_40_MD5  == pSSL->eServerCipher) ||
        (CIPHER_RSA_RC4_128_MD5 == pSSL->eServerCipher) )
    {
        RC4Init(
            &(pSSL->serverCipher),
            pSSL->serverWriteKey,
            sizeof(pSSL->serverWriteKey)
            );
    }
    else
    {
        //Unsupported cipher.
        assert(0);
    }

    //Reset the client write sequence number.
    pSSL->serverSequenceL = 0;
    pSSL->serverSequenceH = 0;

    return nLen;
}


/******************************************************************************
* Function:     CreateServerFinishedMsg
*
* Description:  Create the server finished message
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint CreateServerFinishedMsg
(
    HSSL        pSSL,
    uchar*  pMsgBuff,
    uint   nBuffSize
)
{
    uint    nLen, nEncryptSize = 0;
    uchar*  pMsg = pMsgBuff;
    uchar*  pEncryptData;

    *pMsg++ = CONTENT_HANDSHAKE;

    *pMsg++ = pSSL->preMasterSecret[0]; //SSL_VERSION_MAJOR
    *pMsg++ = (SSL_VERSION_MINOR<pSSL->preMasterSecret[1])?SSL_VERSION_MINOR:pSSL->preMasterSecret[1];

    //Encrypt block size in SSL 3.0. is different from SSL 3.1

    //We will come back to set this correctly.
    *pMsg++ = (uchar)(nEncryptSize>>8);
    *pMsg++ = (uchar)(nEncryptSize>>0);

    //Starting here is data that needs to be encrypted.
    pEncryptData = pMsg;
    nEncryptSize = 0;   //We will come back to calculate correct size.

    *pMsg++ = MSG_FINISHED;
    //We will come back to set this correctly.
    *pMsg++ = (uchar)(nEncryptSize>>16);
    *pMsg++ = (uchar)(nEncryptSize>>8);
    *pMsg++ = (uchar)(nEncryptSize>>0);

    pMsg += nEncryptSize = CreateFinishedMsg(
        pSSL,
        ISSERVER,   //This message comes from server
        pMsg,
        (MD5_SIZE+SHA1_SIZE)
        );

    pEncryptData[1] = (uchar)(nEncryptSize>>16);
    pEncryptData[2] = (uchar)(nEncryptSize>>8);
    pEncryptData[3] = (uchar)(nEncryptSize>>0);

    nEncryptSize += 4;          //Now we add message header size back.

    //Now include the ServerFinishedMessage in the handshake hash.
    DigestMsg(pSSL, pEncryptData, nEncryptSize);

    if (pSSL->eServerCipher != CIPHER_NOTSET)
    {
        //If there is an existing cipher then we need to encrypt the message
        uint   nMacSize = 0;

        pMsg += nMacSize = EncryptWithMAC(
            pSSL,
            ISSERVER,   //We are server
            CONTENT_HANDSHAKE,
            pEncryptData,
            nEncryptSize
            );

        nEncryptSize += nMacSize;
    }

    pEncryptData[-2] = (uchar)(nEncryptSize>>8);
    pEncryptData[-1] = (uchar)(nEncryptSize>>0);

    nLen = pMsg - pMsgBuff;

    assert((uchar)(pMsg - pEncryptData) == nEncryptSize);

    return nLen;
}
