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
*  File Name:       clientMsg.c
*
*  Description:     Generate the Client Hello and other SSL/TLS client messages.
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

#include "clientMsg.h"

#include "cipher.h"
#include "ssl_int.h"
#include "cert.h"
#include "msecret.h"
#include "BN.h"


typedef struct cipher_spec3
{
    uchar   a[2];
} cipher_spec3;

typedef union cipher_spec
{
    uchar   a[3];
    struct {
        uchar           zerobyte;
        cipher_spec3    cipher;
    }   spec3;
} cipher_spec;


const cipher_spec SSL_RSA_WITH_RC4_128_MD5 = {0x00, 0x00, 0x04};
const cipher_spec SSL_RSA_WITH_RC4_128_SHA = {0x00, 0x00, 0x05};
const cipher_spec SSL_EMPTY_RENEGOTIATION = {{0x00, 0x00, 0xFF}};


static uint CreateCertificateMsg(SSL* pSSL, uchar* pMsgBuff, uint nBuffSize);
static uint CreateCertVerifyMsg(SSL* pSSL, uchar* pMsgBuff, uint nBuffSize);
static uint GetClientVerifyInfo(SSL* pSSL, uchar* pMsgBuff);


/******************************************************************************
* Function:     CreateClientHelloMsg
*
* Description:  Create a ClientHello message. We also initialize the SHA1 and
*               MD5 handshake hash context, and hash the ClientHello message.
*               Depends on whether we already have a session ID, we generate
*               either a Version 2.0 or Version 3.0 ClientHello message.
*
* Returns:      Number of bytes of generated ClientHello Message.
******************************************************************************/
uint CreateClientHelloMsg
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
    uint    nCipherSpecLen;

    DigestInit(pSSL);

    memset(&(pSSL->clientRandom), 0, sizeof(pSSL->clientRandom));
    memset(&(pSSL->serverRandom), 0, sizeof(pSSL->serverRandom));

    //We decide whether we want a Version 2.0 or Version 3.0 ClientHello.
    //This is based on whether we already have a session ID.
    if (pSSL->nSessionIDLen == 0)
    {
        //No session ID available. So we create a V.20 ClientHello message
        nCipherSpecLen = sizeof(cipher_spec) * 2;
        nCipherSpecLen+= sizeof(cipher_spec);

        *pMsg++ = 0x80;
        *pMsg++ = (uchar)nLen;  //Need to come back to set this value

        //The hash content begins here. So set the pointer
        pHashData = pMsg;

        *pMsg++ = MSG_CLIENT_HELLO;
        *pMsg++ = SSL_VERSION_MAJOR;
        *pMsg++ = SSL_VERSION_MINOR;

        //Two bytes cipher spec length
        *pMsg++ = (uchar)(nCipherSpecLen>>8);
        *pMsg++ = (uchar)(nCipherSpecLen>>0);

        //Two bytes session ID length
        *pMsg++ = 0x00;
        *pMsg++ = 0x00;

        //Tow bytes challenge length
        *pMsg++ = (uchar)(CHALLENGE_LEN>>8);
        *pMsg++ = (uchar)(CHALLENGE_LEN>>0);

        //Then fill in all the cipher specs. 3 bytes each
        *pMsg++ = SSL_RSA_WITH_RC4_128_MD5.a[0];
        *pMsg++ = SSL_RSA_WITH_RC4_128_MD5.a[1];
        *pMsg++ = SSL_RSA_WITH_RC4_128_MD5.a[2];
        *pMsg++ = SSL_RSA_WITH_RC4_128_SHA.a[0];
        *pMsg++ = SSL_RSA_WITH_RC4_128_SHA.a[1];
        *pMsg++ = SSL_RSA_WITH_RC4_128_SHA.a[2];

        *pMsg++ = SSL_EMPTY_RENEGOTIATION.a[0];
        *pMsg++ = SSL_EMPTY_RENEGOTIATION.a[1];
        *pMsg++ = SSL_EMPTY_RENEGOTIATION.a[2];

        //Fill in the 16 bytes random challenge data
        for (i = CHALLENGE_LEN; i > 0;)
        {
            uint   nRand = 0;  //Intentionally left un-initialized.
            nRand ^= gfRandom();
            pMsg[--i] = (uchar)nRand; nRand >>= 8;
            pMsg[--i] = (uchar)nRand; nRand >>= 8;
            pMsg[--i] = (uchar)nRand; nRand >>= 8;
            pMsg[--i] = (uchar)nRand; nRand >>= 8;
        }

        memcpy(
            &(pSSL->clientRandom[sizeof(pSSL->clientRandom) - CHALLENGE_LEN]),
            pMsg,
            CHALLENGE_LEN
            );
        pMsg += CHALLENGE_LEN;

        //This is the end of what's included in the handshake hash.
        nHashSize = pMsg - pHashData;

        //This is also the end of the ClientHello message.
        nLen    = pMsg - pMsgBuff;

        //Now we come back to fill in the size.
        pMsgBuff[1] = (uchar)nHashSize;
    }
    else
    {
        // We have a Session ID, so we create a V3.0 ClientHello containing
        //the existing Session ID.
        uchar*  p    = &(pSSL->clientRandom[0]);
        uchar*  pEnd = &(pSSL->clientRandom[sizeof(pSSL->clientRandom)]);

        //First construct the ClientRandom
        *p++ = (uchar)((pSSL->nCurrentTime)>>24);
        *p++ = (uchar)((pSSL->nCurrentTime)>>16);
        *p++ = (uchar)((pSSL->nCurrentTime)>>8);
        *p++ = (uchar)((pSSL->nCurrentTime)>>0);
        for ( ; p < pEnd; )
        {
            uint   nRand = 0;  //Intentionally left un-initialized.
            nRand ^= gfRandom();

            *p++ = (uchar)nRand; nRand >>= 8;
            *p++ = (uchar)nRand; nRand >>= 8;
            *p++ = (uchar)nRand; nRand >>= 8;
            *p++ = (uchar)nRand; nRand >>= 8;
        }

        //Now construct the V3.0 ClientHello Message
        *pMsg++ = CONTENT_HANDSHAKE;
        *pMsg++ = SSL_VERSION_MAJOR;
        *pMsg++ = SSL_VERSION_MINOR;

        //The next two bytes are size. We will come back to fill it out
        *pMsg++ = 0;
        *pMsg++ = 0;

        //The hash content begins here. So set the pointer
        pHashData = pMsg;

        //Here starts the actual ClientHello Message
        *pMsg++ = MSG_CLIENT_HELLO;

        //The next 3 bytes are message size. We will come back to fill out.
        *pMsg++ = 0x00;
        *pMsg++ = 0x00;
        *pMsg++ = 0x00;

        //Next two bytes are version
        *pMsg++ = SSL_VERSION_MAJOR;
        *pMsg++ = SSL_VERSION_MINOR;

        //Next 32 bytes are the ClientRandom bytes
        memcpy(pMsg, &(pSSL->clientRandom), sizeof(pSSL->clientRandom));
        pMsg += sizeof(pSSL->clientRandom);

        //Next one byte is the session ID length, and the sessionID.
        *pMsg++ = (uchar)pSSL->nSessionIDLen;
        memcpy(
            pMsg,
            &(pSSL->sessionID[sizeof(pSSL->sessionID) - pSSL->nSessionIDLen]),
            pSSL->nSessionIDLen
            );
        pMsg += pSSL->nSessionIDLen;

        nCipherSpecLen = sizeof(cipher_spec3) * 2;

        *pMsg++ = (uchar)(nCipherSpecLen>>8);
        *pMsg++ = (uchar)(nCipherSpecLen>>0);

        //Next is an array of cipher specs each two bytes.
        *pMsg++ = SSL_RSA_WITH_RC4_128_MD5.spec3.cipher.a[0];
        *pMsg++ = SSL_RSA_WITH_RC4_128_MD5.spec3.cipher.a[1];
        *pMsg++ = SSL_RSA_WITH_RC4_128_SHA.spec3.cipher.a[0];
        *pMsg++ = SSL_RSA_WITH_RC4_128_SHA.spec3.cipher.a[1];

        //Next is Compression Methods List length.
        *pMsg++ = 0x01;

        //Next is the Compression Method list. We only have one.
        *pMsg++ = 0x00; //NULL Compression. None.

        //The secure re-negotiation extention
        nHashSize = 0;
        nHashSize = GetClientVerifyInfo(pSSL, pMsg+7);  //Borrow nHashSize for temporary use
        nHashSize += 5;
        *pMsg++ = (uchar)(nHashSize>>8);
        *pMsg++ = (uchar)(nHashSize>>0);

        *pMsg++ = MSG_EXTENTION;
        *pMsg++ = MSG_EXTENTION_RENEGOTIATION;

        nHashSize -= 4;
        *pMsg++ = (uchar)(nHashSize>>8);
        *pMsg++ = (uchar)(nHashSize>>0);

        nHashSize -= 1;
        *pMsg++ = (uchar)(nHashSize>>0);

        pMsg += nHashSize;

        //That's all. Now we know the whole message length.
        nHashSize = pMsg - pHashData;

        nHashSize -= 4;     //We will add it back on.
        pHashData[2] = (uchar)(nHashSize>>8);
        pHashData[3] = (uchar)(nHashSize>>0);
        nHashSize += 4;     //We then add it back on.

        //Go hack to fill in the content size.
        pHashData[-2] = (uchar)(nHashSize>>8);
        pHashData[-1] = (uchar)(nHashSize>>0);
    }

    DigestMsg(pSSL, pHashData, nHashSize);

    if (pSSL->eClientCipher != CIPHER_NONE)
    {
        //If there is an existing cipher then we need to encrypt the message
        uint   nMacSize = 0;

        pMsg += nMacSize = EncryptWithMAC(
            pSSL,
            ISCLIENT,   //We are client
            CONTENT_HANDSHAKE,
            pHashData,
            nHashSize
            );

        nHashSize += nMacSize;

        //Go hack to fill in the content size.
        pHashData[-2] = (uchar)(nHashSize>>8);
        pHashData[-1] = (uchar)(nHashSize>>0);
    }

    nLen = pMsg - pMsgBuff;

    return nLen;
}


/******************************************************************************
* Function:     CreateCertificateMsg
*
* Description:  Create the certificate message as requested by server. We use
*               the pCertInfo which the application passed to us via nInXData
*               upon the SSL state SSLSTATE_CERTIFICATE_REQUESTING.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint CreateCertificateMsg
(
    SSL*    pSSL,
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uint    n, nLen = 0;
    uchar*  pMsg = pMsgBuff;
    uchar*  pHashData;
    uint    nHashSize;
    const CERTKEY_INFO* pCertInfo = (const CERTKEY_INFO*)pSSL->pTemp;
    const CERTKEY_INFO* pPrev = pCertInfo;

    if (pCertInfo == NULL)
    {
        //No message to be created.
        return 0;
    }

    //The content to be hashed in handshake hash starts here.
    pHashData = pMsg;    

    //First let's figure out how many certificates to be included in the message
    n = 0; nLen = 3;
    pCertInfo = (const CERTKEY_INFO*)pSSL->pTemp;
    for (;;)
    {
        nLen += CERT_SIZE(pCertInfo->pCertificate);
        nLen += 3; //3 bytes for the length
        n ++;
        if (pCertInfo->nKeyLengthBits > 0)
        {
            //This is the last one as nKeyLengthBits is non-zero.
            break;
        }
        else
        {
            pPrev = pCertInfo;
            pCertInfo = pCertInfo->pNext;
        }
    }

    //Do we have enough message buffer?
    if (nBuffSize < (nLen +4))
    {
        //Buffer too small, so construct no message.
        //assert(0);
        return 0;
    }

    //The very first byte of course is MSG_CERTIFICATE
    *pMsg++ = MSG_CERTIFICATE;

    //Now we have the length so set total message size in the message
    *pMsg++ = (uchar)(nLen>>16);
    *pMsg++ = (uchar)(nLen>>8 );
    *pMsg++ = (uchar)(nLen>>0 );

    nLen -= 3;
    //Set the total certificate package size.
    *pMsg++ = (uchar)(nLen>>16);
    *pMsg++ = (uchar)(nLen>>8 );
    *pMsg++ = (uchar)(nLen>>0 );

    //Now for each certificate. We do it in reverse order.
    for (;;)
    {
        nLen = CERT_SIZE(pCertInfo->pCertificate);

        //This one certificate size.
        *pMsg++ = (uchar)(nLen>>16);
        *pMsg++ = (uchar)(nLen>>8 );
        *pMsg++ = (uchar)(nLen>>0 );

        //The certificate itself
        memcpy(pMsg, pCertInfo->pCertificate, nLen);
        pMsg += nLen;

        if (pPrev == pCertInfo)
        {
            //The very first one is the last one to be put into message.
            break;
        }
        else
        {
            pCertInfo = pPrev;
            pPrev = pCertInfo->pPrev;
            if (pPrev == NULL)
            {
                pPrev = pCertInfo;
            }
        }
    }

    nHashSize = (pMsg - pHashData);

    //Hash the handshake content of just ServerHello
    DigestMsg(pSSL, pHashData, nHashSize);

    return (nLen = pMsg - pMsgBuff);
}


/******************************************************************************
* Function:     CreateCertVerifyMsg
*
* Description:  Create the certificate verify message as server requested client
*               authentication. Necessary RSA key was passed in by application
*               via nInXData upon the SSL state SSLSTATE_CERTIFICATE_REQUESTING.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint CreateCertVerifyMsg
(
    SSL*    pSSL,
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uint    nLen=0, nKeyLen=0, nPubExp=0;
    uchar*  pMsg = pMsgBuff;
    uchar*  pHashData;
    uint    nHashSize;
    const CERTKEY_INFO* pCertInfo = (const CERTKEY_INFO*)pSSL->pTemp;
    uchar*  pMd5Digest;
    uchar*  pSha1Digest;
    EBLOCK  u;

    if (pCertInfo == NULL) {return 0;} //No message to be created.

    //We are only interested in the pCertInfo with key length set: The main client cert.
    while (pCertInfo->nKeyLengthBits == 0)
    {
        pCertInfo = pCertInfo->pNext;
    }

    {
        //We need to get the public exponent from the certificate
        CERT*   pCert;
        uchar   pubKey[256];
        
        pCert = CreateCert(CS_UNKNOWN, pSSL->nCurrentTime);
        ParseCert(pCert, pCertInfo->pCertificate, CERT_SIZE(pCertInfo->pCertificate));

        GetPubKey(pCert, pubKey);

        nPubExp = GetPubExp(pCert);

        DestroyCert(pCert);
    }

    nKeyLen = (pCertInfo->nKeyLengthBits + 7) >> 3;  //RSA key length in bytes

    //Calculate where we are going to put the final digests
    pSha1Digest = &(u.encryptBlock[nKeyLen]);
    pSha1Digest -= SHA1_SIZE;
    pMd5Digest  = pSha1Digest - MD5_SIZE;

    //The content to be hashed in handshake hash starts here.
    pHashData = pMsg;

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
    memcpy(pMd5Digest, u.md5Digest, MD5_SIZE);

    memset(u.encryptBlock, 0xFF, nKeyLen - (MD5_SIZE+SHA1_SIZE));
    u.encryptBlock[0] = 0x00;
    u.encryptBlock[1] = 0x01;
    pMd5Digest[-1] = 0x00;

    BN_Decrypt(
        u.encryptBlock,
        pCertInfo->pPublicKey,
        pCertInfo->pPrivateKey,
        nKeyLen
        );

    //OK, now we can construct the actual certificate verify message.

    //The very first byte of course is MSG_CERTIFICATE
    *pMsg++ = MSG_CERTIFICATE_VERIFY;

    //Now we have the length so set total message size in the message
    nLen = nKeyLen+2;
    *pMsg++ = (uchar)(nLen>>16);
    *pMsg++ = (uchar)(nLen>>8 );
    *pMsg++ = (uchar)(nLen>>0 );

    nLen -= 2;
    *pMsg++ = (uchar)(nLen>>8 );
    *pMsg++ = (uchar)(nLen>>0 );

    memcpy(pMsg, u.encryptBlock, nLen);
    pMsg += nLen;

    nHashSize = pMsg - pHashData;

    //Hash the handshake content of certificate verify message
    DigestMsg(pSSL, pHashData, nHashSize);

    return (nLen = pMsg - pMsgBuff);
}


/******************************************************************************
* Function:     CreateClientKeyExchangeMsg
*
* Description:  Create the client key exchange message.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint CreateClientKeyExchangeMsg
(
    HSSL    pSSL,
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    uint    i, nLen = 0, nKeyLen;
    uchar*  pMsg = pMsgBuff;
    uchar*  pEncryptData;
    uchar*  pHashData0;
    uchar*  pHashData;
    uint    nHashSize;
    uint    nUsed = 0;
    uint    nRand = 0;  //Intentionally left un-initialized.

    if ((NULL == pSSL->pServerCert) ||
        (0 == (nKeyLen = GetPubKeyLen(pSSL->pServerCert))) )
    {
        //We do not have server certificate. Can not proceed.
        return 0;
    }

    //Now construct the ClientKeyExchange message. We know the message
    //size because we already know the server public key length.

    //First generate the 48 bytes Pre-Master Secret.
    for (i=PRE_MASTER_SECRET_LEN; i>0; )
    {
        nRand ^= gfRandom();
        pSSL->preMasterSecret[--i] = (uchar)nRand; nRand >>= 8;
        pSSL->preMasterSecret[--i] = (uchar)nRand; nRand >>= 8;
        pSSL->preMasterSecret[--i] = (uchar)nRand; nRand >>= 8;
        pSSL->preMasterSecret[--i] = (uchar)nRand; nRand >>= 8;
    }
    //The first 2 bytes of Pre-Master Secret is Version
    pSSL->preMasterSecret[0] = SSL_VERSION_MAJOR;
    pSSL->preMasterSecret[1] = SSL_VERSION_MINOR;

    //Now we starts to construct the whole Client Exchange Message
    *pMsg++ = CONTENT_HANDSHAKE;
    *pMsg++ = SSL_VERSION_MAJOR;
    *pMsg++ = SSL_VERSION_MINOR;

    //We will come back here to fill in the total content size
    nHashSize = nKeyLen + 4;
    *pMsg++ = (uchar)(nHashSize>>8);
    *pMsg++ = (uchar)(nHashSize>>0);

    //Here starts the message body that needs to be hashed.
    pHashData0 = pMsg;

    //1.The client certificate(s) message
    pMsg += nUsed = CreateCertificateMsg(pSSL, pMsg, nBuffSize - (pMsg-pMsgBuff));

    //2. The Client Key Exchange message
    pHashData = pMsg;

    *pMsg++ = MSG_CLIENT_KEY_EXCHANGE;
    *pMsg++ = (uchar)(nKeyLen>>16);
    *pMsg++ = (uchar)(nKeyLen>>8);
    *pMsg++ = (uchar)(nKeyLen>>0);

    //Here starts the data that needs to be encrypted.
    pEncryptData = pMsg;
    //First fill the pre padding with all none-zero random bytes
    for (i=nKeyLen-PRE_MASTER_SECRET_LEN; i>0; )
    {
        uchar byteRand;
        while (0x00 == (byteRand = (uchar)gfRandom())) {}
        pMsg[--i] = byteRand;
    }
    pEncryptData[0] = 0x00;
    pEncryptData[1] = 0x02; //Block type 2, See PKCS#1
    pMsg += nKeyLen-PRE_MASTER_SECRET_LEN;
    pMsg[-1] = 0x00;

    //Now fill in the PreMasterSecret. Making the total nKeyLen.
    memcpy(pMsg, pSSL->preMasterSecret, PRE_MASTER_SECRET_LEN);
    pMsg += PRE_MASTER_SECRET_LEN;

    nLen = pMsg - pMsgBuff;

    //Now Encrypt it using server public key.
    EncryptByCert(pSSL->pServerCert, pEncryptData, nKeyLen);

    //Now hash just the client key exchange message
    nHashSize = pMsg - pHashData;
    DigestMsg(pSSL, pHashData, nHashSize);

    //At this point the MasterSecret can be calculated. We do it here
    //because we need it to create the certificate verify message.
    //This calculation may be duplicated later but OK.
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

    //3. The client certificate verify message
    pMsg += nUsed = CreateCertVerifyMsg(pSSL, pMsg, nBuffSize - (pMsg-pMsgBuff));

    //Now calculate total content size
    nHashSize = (pMsg - pHashData0);

    if (pSSL->eClientCipher != CIPHER_NONE)
    {
        uint   nMacSize;

        pMsg += nMacSize = EncryptWithMAC(
            pSSL,
            ISCLIENT,   //We are client
            CONTENT_HANDSHAKE,
            pHashData0,
            nHashSize
            );

        nHashSize += nMacSize;
    }

    //Now go back to fill in the Handshake Content Size.
    pHashData0[-2] = (uchar)(nHashSize>>8);
    pHashData0[-1] = (uchar)(nHashSize>>0);

    //Finally hash all content.
    nLen = (pMsg - pMsgBuff);

    return nLen;
}


/******************************************************************************
* Function:     CreateChangeCipherSpecMsg
*
* Description:  Create the change cipher spec message
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint CreateChangeCipherSpecMsg
(
    HSSL        pSSL,
    uchar*  pMsgBuff,
    uint   nBuffSize
)
{
    uint       nLen, nDataSize;
    uchar*      pMsg = pMsgBuff;
    uchar*      pMsgBody;

    *pMsg++ = CONTENT_CHANGECIPHERSPEC;
    *pMsg++ = SSL_VERSION_MAJOR;
    *pMsg++ = (pSSL->preMasterSecret[1]<SSL_VERSION_MINOR)?pSSL->preMasterSecret[1]:SSL_VERSION_MINOR;

    //The Message Body is 1 byte: That byte is 0x01.
    *pMsg++ = 0x00;
    *pMsg++ = 0x01; //The message length

    pMsgBody = pMsg;
    *pMsg++ = 0x01; //The message body

    nDataSize = pMsg - pMsgBody;

    if (pSSL->eClientCipher != CIPHER_NONE)
    {
        uint   nMacSize;

        pMsg += nMacSize = EncryptWithMAC(
            pSSL,
            ISCLIENT,   //We are client
            CONTENT_CHANGECIPHERSPEC,
            pMsgBody,
            nDataSize
            );

        nDataSize += nMacSize;
    }

    pMsgBody[-2] = (uchar)(nDataSize>>8);
    pMsgBody[-1] = (uchar)(nDataSize>>0); 

    nLen = pMsg - pMsgBuff;

    //It is also time to calculate MasterSecret from PreMasterSecret.
    //Derive encryption keys from MasterSecret, and initialize cipher.
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

    //Initialize the server write cipher.
    if ((CIPHER_RSA_RC4_40_MD5  == pSSL->eClientCipher) ||
        (CIPHER_RSA_RC4_128_MD5 == pSSL->eClientCipher) ||
        (CIPHER_RSA_RC4_128_SHA == pSSL->eClientCipher) )
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
    }

    //Reset the client write sequence number.
    pSSL->clientSequenceL = 0;
    pSSL->clientSequenceH = 0;

    return nLen;
}


/******************************************************************************
* Function:     CreateClientFinishedMsg
*
* Description:  Create the client finished message to verify handshake OK.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint CreateClientFinishedMsg
(
    HSSL        pSSL,
    uchar*  pMsgBuff,
    uint   nBuffSize
)
{
    uint       nLen, nMacSize=MD5_SIZE, nHashSize;
    uchar*      pMsg = pMsgBuff;
    uchar*      pHashData;

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
        nMacSize = MD5_SIZE;
        break;
    }

    *pMsg++ = CONTENT_HANDSHAKE;

    *pMsg++ = pSSL->preMasterSecret[0]; //SSL_VERSION_MAJOR;
    *pMsg++ = pSSL->preMasterSecret[1]; //SSL_VERSION_MINOR;

    nHashSize = 0;
    //Tentative size may not be correct. Will come back to put in the correct size.
    //nHashSize = 4 + (MD5_SIZE + SHA1_SIZE) + nMacSize;

    *pMsg++ = (uchar)(nHashSize>>8);
    *pMsg++ = (uchar)(nHashSize>>0);

    //Starting here is data that needs to be encrypted.
    pHashData = pMsg;
    //nHashSize -= nMacSize;   //We will add it back later
    //nHashSize -= 4;          //We will add it back later

    *pMsg++ = MSG_FINISHED;
    *pMsg++ = (uchar)(nHashSize>>16);
    *pMsg++ = (uchar)(nHashSize>>8);
    *pMsg++ = (uchar)(nHashSize>>0);
    //nHashSize += 4;          //Now we add it back.

    pMsg += CreateFinishedMsg(
        pSSL,
        ISCLIENT,   //This message is from client
        pMsg,
        (MD5_SIZE+SHA1_SIZE)
        );

    nHashSize = (pMsg-pHashData);

    nHashSize   -= 4; //Not counting the four bytes header.
    pHashData[2] = (uchar)(nHashSize>>8);
    pHashData[3] = (uchar)(nHashSize>>0);
    nHashSize   += 4; //Add the header size back for hash.

    //Now include the ClientFinishedMessage in the handshake hash.
    DigestMsg(pSSL, pHashData, nHashSize);

    //Now calculate the MAC of the message and encrypt
    pMsg += nMacSize = EncryptWithMAC(
        pSSL,
        ISCLIENT,   //For Client
        (*pMsgBuff),
        pHashData,
        nHashSize
        );

    nHashSize += nMacSize;  //Add the MAC size to total content size.

    //Fill in the content size.
    pHashData[-2] = (uchar)(nHashSize>>8);
    pHashData[-1] = (uchar)(nHashSize>>0); 

    return (nLen = pMsg - pMsgBuff);
}


/******************************************************************************
* Function:     VerifyServerMAC
*
* Description:  Verify that the server message contains the correct MAC.
*
* Returns:      ZERO if the message integrity is verified. Else none-zero.
******************************************************************************/
uint VerifyServerMAC
(
    HSSL                pSSL,
    uchar           cMsgType,   //Content Type. e.g., CONTENT_HANDSHAKE
    const uchar*    pMsg,       //Pointer to the message.
    uint*          pSize       //Passed in: MAC size included; Passed out: MAC size subtracted.
)
{
    uint   nMacSize, nMsgSize;
    uchar   digest[SHA1_SIZE]; //MAX(SHA1_SIZE, MD5_SIZE)

    switch (pSSL->eServerCipher)
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
        nMacSize = 0;
        break;
    }

    if ((*pSize) < nMacSize)
    {
        //Bad formed message. Good message should include at least a MAC size.
        return -1;
    }
    nMsgSize = (*pSize) - nMacSize;

    nMacSize = CalculateMAC(
        pSSL,
        ISSERVER,   //This is a message from a server.
        digest,
        cMsgType,
        pMsg,
        nMsgSize
        );

    *pSize = nMsgSize;

    return memcmp(&(pMsg[nMsgSize]), digest, nMacSize);
}


/******************************************************************************
* Function:     GetClientVerifyInfo
*
* Description:  Extract the client verify info block which was generated in a
*               previous client finished message. This would only exist if there
*               was a previous successful handshake. The block is 36 bytes for
*               SSL 3.0, and 12 bytes for SSL 3.1/TLS 1.0 or later.
*
* Returns:      Bytes of the client verify info copied. Zero if there is none.
******************************************************************************/
uint GetClientVerifyInfo
(
    SSL*        pSSL,
    uchar*  pMsgBuff
)
{
    uint   nVerifySize;

    if (pSSL->eClientCipher == CIPHER_NONE)
    {
        //No prior handshake, so the client verify info does not exist.
        nVerifySize = 0;
    }
    else  if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
    {
        //For SSL 3.0. The verify info is MD5_SIZE + SHA1_SIZE = 36 bytes 
        nVerifySize = MD5_SIZE + SHA1_SIZE;
        memcpy(pMsgBuff, pSSL->clientVerify, nVerifySize);
    }
    else
    {
        //For SSL 3.1. The verify info is TLS_VERIFY_LEN=12 bytes;
        nVerifySize = TLS_VERIFY_LEN;
        memcpy(pMsgBuff, pSSL->clientVerify, nVerifySize);
    }

    return nVerifySize;
}
