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
*  File Name:       sslServer.c
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

#include <string.h>
#include <assert.h>
#include <stdint.h>


#include "cert.h"
#include "sslServer.h"
#include "serverMsg.h"
#include "ssl_int.h"
#include "cipher.h"


#define CONTENT_HEADER_LEN      5


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

extern uint gSvrMsgSize;
extern uint gAppMsgSize;

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


static uint ParseClientMsg(SSL* pSSL, const uchar* pMsg, uint nMsgLen);
static uint ParseClientHello(SSL* pSSL, const uchar* pMsg, uint nMsgSize);
static uint ParseClientHello2(SSL* pSSL, const uchar* pMsg, uint nMsgSize);
static uint ParseClientHandshake(SSL* pSSL, const uchar* pMsg, uint nMsgSize);
static uint VerifyClientFinished(SSL* pSSL, const uchar* pMsg, uint nMsgSize);
static uint CreateAlertMsg(SSL* pSSL, uchar cCategory, uchar cType);
static uint CreateServerMsg(SSL* pSSL, uchar cContentType, const uchar* pData, uint nDataSize);


/******************************************************************************
* Function:     SSL_Server
*
* Description:  The main SSL server processing function. This is repeatedly
*               called to update the state machine.
*
* Returns:      Zero if no error, or an error code.
******************************************************************************/
SSL_RESULT SSL_Server
(
    SSL_PARAMS* pParam,
    HSSL        pSSL
)
{
    uint    nParsed = 0;

    if ((NULL == pSSL) || (NULL == pParam))
    {
        return SSL_ERROR_GENERIC;
    }

    //Reset return parameters so we do not unintentionally return something.
    pParam->pNetOutData = NULL;
    pParam->nNetOutSize = 0;
    pParam->pAppOutData = NULL;
    pParam->nAppOutSize = 0;
    pSSL->nNetOutSize = 0;
    pSSL->nAppOutSize = 0;

    //Update our time. The time is a UINT32 count of seconds since
    //the EPOCH, 00:00AM 01/01/1970 UTC.
    pSSL->nCurrentTime = pParam->nUnixTime;

    //Second do we have a state change?
    if (pParam->eState != pSSL->eState)
    {
        pSSL->eState = pParam->eState;
        switch (pSSL->eState)
        {
        case SSLSTATE_TCPCONNECTED:
            {
                pSSL->eState = SSLSTATE_HANDSHAKE_BEGIN;
                pSSL->nStartTime = pSSL->nCurrentTime;
                pSSL->eClientCipher = CIPHER_NOTSET;
                pSSL->eServerCipher = CIPHER_NOTSET;

                pSSL->serverMsgOff = 0;
                pSSL->serverMsgLen = 0;

                pSSL->preMasterSecret[0] = SSL_VERSION_MAJOR;
                pSSL->preMasterSecret[1] = SSL_VERSION_MINOR;

                //We wait for a ClientHello message first.
                pSSL->eState = SSLSTATE_CLIENT_HELLO;
            }
            break;

        case SSLSTATE_HELLO_REQUEST:
            {
                pSSL->nNetOutSize += CreateHelloRequestMsg(
                    pSSL,
                    &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                    (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                    );
                pSSL->eState = SSLSTATE_CLIENT_HELLO;
            }
            break;

        case SSLSTATE_DISCONNECT:
            {
                //We were told by the App to initiate disconnect sequence.
                //This is done by sending a Close Alert to the client, then
                //notify the App to disconnect the TCP.
                CreateAlertMsg(pSSL, ALERT_WARNING, ALERT_NOTIFY_CLOSE);
                pSSL->eState = SSLSTATE_DISCONNECTING;
            }
            break;

        case SSLSTATE_DISCONNECTED:
            {
                //Do some cleanup and prepare for next connection.
                pSSL->eState = SSLSTATE_UNCONNECTED;
            }
            break;
        default:
            break;
        }
    }
    pParam->eState = pSSL->eState;

    //Third do we have anything from the network?
    nParsed = 0;
    while ((NULL != pParam->pNetInData) && (nParsed < pParam->nNetInSize))
    {
        nParsed += ParseClientMsg(
            pSSL, 
            pParam->pNetInData + nParsed,
            pParam->nNetInSize - nParsed
            );
    }

    //Fourth do we have any state change because of server message parsing?
    do
    {
        pParam->eState = pSSL->eState;
        switch (pSSL->eState)
        {
        case SSLSTATE_CLIENT_CERTREQUEST:
            //Defaulting to not request client certificate. Unless the application
            //code later requests client certificate by setting nInXData to TRUE.
            pParam->nInXData.data = 0;
            pSSL->pTemp = NULL;
            pParam->eState = pSSL->eState = SSLSTATE_SERVER_HELLO;
            break;

        case SSLSTATE_SERVER_HELLO:
            if (pParam->nInXData.data)
            {
                //We will do client certificate request
                pSSL->pTemp = pSSL->serverMsg;  //Just set to none NULL.
            }
            else
            {
                //We will NOT do client certificate request.
                pSSL->pTemp = NULL;
            }
            pSSL->nNetOutSize += CreateServerHelloMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            break;

        case SSLSTATE_CERTIFICATE_VERIFY:
            {
                //Verify server certificate.
                CERT_STATUS eStatus;

                eStatus = AuthenticateCert(pSSL->pServerCert, NULL);

                pSSL->eState = SSLSTATE_CERTIFICATE_VERIFIED;
            }
            break;

        case SSLSTATE_CERTIFICATE_VERIFIED:
            pSSL->eState = SSLSTATE_CLIENT_KEYEXCHANGE;
            break;

        case SSLSTATE_CERTIFICATE_REJECTED:
            pParam->eState = pSSL->eState = SSLSTATE_ABORTING;
            break;

        case SSLSTATE_CLIENT_KEYEXCHANGE:
            //Wait for ClientKeyExchange and go to SSLSTATE_CLIENT_FINISH1
            break;

        case SSLSTATE_SERVER_FINISH1:
            //First send the ServerChangeCipherSpec message.
            pSSL->nNetOutSize += CreateServerChangeCipherMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            //Then send the ServerFinished message.
            pSSL->nNetOutSize += CreateServerFinishedMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            pSSL->eState = SSLSTATE_CLIENT_FINISH2;
            break;

        case SSLSTATE_SERVER_FINISH2:
            //First send the ServerChangeCipherSpec message.
            pSSL->nNetOutSize += CreateServerChangeCipherMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            //Then send the ServerFinished message.
            pSSL->nNetOutSize += CreateServerFinishedMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            pSSL->eState = SSLSTATE_HANDSHAKE_DONE;
            break;

        case SSLSTATE_HANDSHAKE_DONE:
            //TODO: Check everything to make sure it is OK.
            pSSL->eState = SSLSTATE_CONNECTED;
            break;

        case SSLSTATE_CONNECTED:
            //Nothing to do here. We remain fully connected indefinitely.
            break;

        case SSLSTATE_ABORT:
            //There is an internal error processing the incoming message, so bail out
            pParam->eState = pSSL->eState = SSLSTATE_ABORTING;
            break;

        case SSLSTATE_ABORTING:
            //TODO: Need to send an abort message to the server here.
            //After the abort message is sent. Set the below state. Application then
            //should disconnect the TCP, and change state to SSLSTATE_DISCONNECTED.
            pSSL->eState = SSLSTATE_ABORTED;
            break;

        case SSLSTATE_ABORTED:
            pParam->eState = pSSL->eState = SSLSTATE_DISCONNECT;
            break;

        default:
            break;
        }
    } while (pParam->eState != pSSL->eState);


    //Fifth do we have any application data that needs to be sent out?
    if ((pParam->nAppInSize > 0) && (NULL != pParam->pAppInData))
    {
        uint    nMsgSize;

        if (pSSL->eServerCipher == CIPHER_NOTSET)
        {
            return SSL_ERROR_NOTREADY;
        }

        nMsgSize = CreateServerMsg(
            pSSL,
            CONTENT_APPLICATION_DATA,
            pParam->pAppInData,
            pParam->nAppInSize
            );
    }

    //Finally return anything that needs to be returned to the caller.
    if (pSSL->nNetOutSize > 0)
    {
        pParam->pNetOutData = pSSL->netoutMsg;
        pParam->nNetOutSize = pSSL->nNetOutSize;
    }

    if (pSSL->nAppOutSize > 0)
    {
        pParam->pAppOutData = pSSL->appoutMsg;
        pParam->nAppOutSize = pSSL->nAppOutSize;
    }

    return SSL_OK;
}


/******************************************************************************
* Function:     ParseClientMsg
*
* Description:  Parse a generic client message
*
* Returns:      Bytes of message parsed.
******************************************************************************/
uint ParseClientMsg
(
    SSL*            pSSL,
    const uchar*    pServerMsg,
    uint            nMsgLen
)
{
    uint nCopied = 0;
    uint nParsed = 0;
    uchar*  pMsg;

    while ((nMsgLen > 0) || (nParsed > 0))
    {
        uint    nCopySize = 0;
        uchar   cContentType, verMajor, verMinor;
        uint    nContentSize = 0, nMsgSize;

        // First re-align any remainder server message to the beginning
        // of buffer pSSL->serverMsg, if there is unaligned message
        // data from previous parsing. But do it only when we are ready
        // to copy more data from input.
        if ((pSSL->serverMsgOff > 0) && (nMsgLen > 0))
        {
            if (pSSL->serverMsgLen > 0)
            {
                memmove(
                    pSSL->serverMsg,
                    pSSL->serverMsg+pSSL->serverMsgOff,
                    pSSL->serverMsgLen
                    );
            }
            pSSL->serverMsgOff = 0;
        }

        // Second copy what we can from input buffer into pSSL->serverMsg buffer.
        nCopySize = gSvrMsgSize - pSSL->serverMsgLen - pSSL->serverMsgOff;
        if (nCopySize > nMsgLen)
        {
            nCopySize = nMsgLen;
        }

        if (nCopySize > 0)
        {
            memcpy(pSSL->serverMsg+pSSL->serverMsgOff, pServerMsg, nCopySize);
            pSSL->serverMsgLen += nCopySize;
            pServerMsg    += nCopySize;
            nCopied += nCopySize;
            nMsgLen -= nCopySize;
        }
        else if (nParsed == 0)
        {
            // The buffer is totally full or we have nothing more to copy.
            // So do not process any more, unless in the last round we have
            // just parsed portion of the message.
            break;
        }

        // Third parse the message in pSSL->serverMsg. One at a time.
        nParsed = 0;
        pMsg = pSSL->serverMsg + pSSL->serverMsgOff;

        // The CONTENT_HEADER_LEN = 5 bytes goes like this:
        // 1 content type
        // 1 major version
        // 1 minor version
        // 2 content length (MSB LSB)
        if (pSSL->serverMsgLen < CONTENT_HEADER_LEN)
        {
            continue;
        }

        if (*pMsg == 0x80)
        {
            //Special case, first ClientHello in V.20 format.
            pMsg ++;
            nContentSize = *pMsg++;
            if (pSSL->serverMsgLen < 2 + nContentSize)
            {
                // We do not have the complete message yet.
                continue;
            }

            ParseClientHello2(pSSL, pMsg, nContentSize);

            nParsed = 2 + nContentSize;
            pSSL->serverMsgOff += nParsed;
            pSSL->serverMsgLen -= nParsed;
            continue;

        }

        cContentType = *pMsg++;
        verMajor     = *pMsg++;
        verMinor     = *pMsg++;
        nContentSize = *pMsg++;
        nContentSize <<= 8;
        nContentSize += *pMsg++;

        assert(verMajor == SSL_VERSION_MAJOR);
        //assert(verMinor == SSL_VERSION_MINOR);

        if (pSSL->serverMsgLen < CONTENT_HEADER_LEN + nContentSize)
        {
            // We do not have the complete message yet.
            continue;
        }

        nMsgSize = nContentSize;    //nMsgSize is nContentSize minus the MAC

        //If the cipher has been turned on already. Then we need to decrypt
        switch (pSSL->eClientCipher)
        {
        case CIPHER_NOTSET:
            //No need to decrypt.
            break;
        case CIPHER_RSA_RC4_40_MD5:
        case CIPHER_RSA_RC4_128_MD5:
        case CIPHER_RSA_RC4_128_SHA:
            RC4Code(&(pSSL->clientCipher), pMsg, nContentSize);
            if (0 == VerifyClientMAC(pSSL, cContentType, pMsg, &nMsgSize))
            {
                //We are OK.
            }
            else
            {
                //Corrupted message.
                pSSL->eState = SSLSTATE_ABORT; //Bail out.
            }
            break;
        default:
            //Unsupported cipher.
            assert(0);
            break;
        }

        switch (cContentType)
        {
        case CONTENT_CHANGECIPHERSPEC:
            ParseClientChangeCipherSpec(pSSL, pMsg, nMsgSize);
            break;
        case CONTENT_ALERT:
            ParseAlertMsg(pSSL, pMsg, nMsgSize);
            break;
        case CONTENT_HANDSHAKE:
            ParseClientHandshake(pSSL, pMsg, nMsgSize);
            break;
        case CONTENT_APPLICATION_DATA:
            ParseAppData(pSSL, pMsg, nMsgSize);
            break;
        default:
            assert(0);  // Unknown content type
            break;
        }

        nParsed = CONTENT_HEADER_LEN + nContentSize;
        pSSL->serverMsgOff += nParsed;
        pSSL->serverMsgLen -= nParsed;
    }

    // Just for debugging
    //if (pSSL->serverMsgLen >= pSSL->uiServerMessageSize)
    //if (pSSL->serverMsgLen >= sizeof(pSSL->serverMsg))
    if (pSSL->serverMsgLen >= gSvrMsgSize)
    {
        // We must not have big enough buffer size.
        // Need to increase pSSL->serverMsg.
        assert(0);
    }

    return nCopied;
}


/******************************************************************************
* Function:     ParseClientHello2
*
* Description:  Parse ClientHello in SSL V2.0 format.
*
* Returns:      Bytes of message parsed.
******************************************************************************/
uint ParseClientHello2
(
    SSL*            pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uchar   vMajor, vMinor;
    int             nCiphers = 0;
    int             nSessionIDLen = 0;
    int             nClientRandomLen = 0;
    uint    theCipher = CIPHER_NOTSET;
    const uchar*    p = pMsg;

    assert((*p) == MSG_CLIENT_HELLO);

    DigestInit(pSSL);

    p++;
    vMajor = *p++;
    vMinor = *p++;

    assert(vMajor == SSL_VERSION_MAJOR);
    //assert(vMinor == SSL_VERSION_MINOR);

    //We will use client SSL version
    pSSL->preMasterSecret[0] = vMajor;
    pSSL->preMasterSecret[1] = (vMinor>SSL_VERSION_MINOR)?SSL_VERSION_MINOR:vMinor;

    nCiphers += *p++;
    nCiphers <<= 8;
    nCiphers += *p++;

    nSessionIDLen += *p++;
    nSessionIDLen <<= 8;
    nSessionIDLen += *p++;

    nClientRandomLen += *p++;
    nClientRandomLen <<= 8;
    nClientRandomLen += *p++;

    while (nCiphers >= 3)
    {
        theCipher = *p++;
        theCipher <<= 8;
        theCipher += *p++;
        theCipher <<= 8;
        theCipher += *p++;

        nCiphers -= 3;

        if (pSSL->ePendingCipher == CIPHER_RSA_RC4_128_MD5)
        {
            //We already have the best cipher. No change.
        }
        else if (theCipher == CIPHER_RSA_RC4_128_MD5)
        {
            pSSL->ePendingCipher = CIPHER_RSA_RC4_128_MD5;
        }
        else if (pSSL->ePendingCipher == CIPHER_NOTSET)
        {
            pSSL->ePendingCipher = theCipher;
        }
        else if (theCipher == CIPHER_RSA_RC4_128_SHA)
        {
            pSSL->ePendingCipher = theCipher;
        }
    }

    if ((nSessionIDLen > 0) &&
        (nSessionIDLen == (int)pSSL->nSessionIDLen) &&
        (0 == memcmp(&(pSSL->sessionID[sizeof(pSSL->sessionID)-nSessionIDLen]), p, nSessionIDLen)) )
    {
        //Session ID matches, resume previous session.
    }
    else
    {
        //Trigger the generation of a random session ID upon sending ServerHello.
        pSSL->nSessionIDLen = 0;
    }
    p += nSessionIDLen;

    memset(&(pSSL->clientRandom), 0, sizeof(pSSL->clientRandom));
    memcpy(&(pSSL->clientRandom[sizeof(pSSL->clientRandom)-nClientRandomLen]), p, nClientRandomLen);
    p += nClientRandomLen;

    DigestMsg(pSSL, pMsg, nMsgSize);

    //Send out ServerHello next.
    pSSL->eState = SSLSTATE_CLIENT_CERTREQUEST;

    assert((uint)(p - pMsg) == nMsgSize);

    return (uint)(p - pMsg);
}


/******************************************************************************
* Function:     ParseClientHello
*
* Description:  Parse ClientHello in SSL V3.0 format.
*
* Returns:      Bytes of message parsed.
******************************************************************************/
uint ParseClientHello
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uchar   vMajor, vMinor;
    int             nCiphers = 0;
    int             nSessionIDLen = 0;
    int             nCompression;
    uint    theCipher = CIPHER_NOTSET;
    const uchar*    p = pMsg;

    vMajor = *p++;
    vMinor = *p++;

    assert(vMajor == SSL_VERSION_MAJOR);

    pSSL->preMasterSecret[0] = vMajor;
    pSSL->preMasterSecret[1] = (vMinor>SSL_VERSION_MINOR)?SSL_VERSION_MINOR:vMinor;

    DigestInit(pSSL);

    memcpy(pSSL->clientRandom, p, CLIENT_RANDOM_SIZE);
    p += CLIENT_RANDOM_SIZE;

    //Does the ClientHello contain an existing SessionID?
    nSessionIDLen = *p++;
    if ((nSessionIDLen > 0) &&
        (nSessionIDLen == (int)pSSL->nSessionIDLen) &&
        (0 == memcmp(&(pSSL->sessionID[sizeof(pSSL->sessionID)-nSessionIDLen]), p, nSessionIDLen)) )
    {
        //Session ID matches, resume previous session.
    }
    else
    {
        //Trigger the generation of a random session ID upon sending ServerHello.
        pSSL->nSessionIDLen = 0;
    }
    p += nSessionIDLen;


    nCiphers += *p++;
    nCiphers <<= 8;
    nCiphers += *p++;

    while (nCiphers >= 2)
    {
        theCipher = *p++;
        theCipher <<= 8;
        theCipher += *p++;

        nCiphers -= 2;

        if (pSSL->ePendingCipher == CIPHER_RSA_RC4_128_MD5)
        {
            //We already have the best cipher. No change.
        }
        else if (theCipher == CIPHER_RSA_RC4_128_MD5)
        {
            pSSL->ePendingCipher = CIPHER_RSA_RC4_128_MD5;
        }
        else if (pSSL->ePendingCipher == CIPHER_NOTSET)
        {
            pSSL->ePendingCipher = theCipher;
        }
        else if (theCipher == CIPHER_RSA_RC4_128_SHA)
        {
            pSSL->ePendingCipher = theCipher;
        }
    }

    nCompression = *p++;
    p += nCompression;

    //Send out ServerHello next.
    pSSL->eState = SSLSTATE_SERVER_HELLO;

    if ((uint)(p - pMsg) < nMsgSize)
    {
        uint nLen = 0;
        //This is probably client of SSL V3.1. There is some extra stuff
        //in the client hello, probably maxinum RSA key size?
        //The message looks like this:
        //  00 05
        //  FF
        //  01 00
        //  01 00
        //We don't care for now. May come back to exam it later.
        nLen += *p++;
        nLen <<= 8;
        nLen += *p++;

        //Just skip the next nLen bytes
        p += nLen;
    }

    assert((uint)(p - pMsg) == nMsgSize);

    return (uint)(p - pMsg);
}


/******************************************************************************
* Function:     ParseClientHandshake
*
* Description:  Process the client handshake message
*
* Returns:      Bytes of message parsed, or a negative error code
******************************************************************************/
uint ParseClientHandshake
(
    SSL*            pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uchar   cMsgType;
    uint    nMsgLen;
    uint    nParsed = 0;

    if (nMsgSize < 4)
    {
        return SSL_ERROR_PARSE;
    }

    while (nParsed < nMsgSize)
    {
        uint        nParseSize;
        const uchar*    pHashData;

        pHashData = pMsg;
        cMsgType = *pMsg++;
        nMsgLen  = *pMsg++;
        nMsgLen <<= 8;
        nMsgLen += *pMsg++;
        nMsgLen <<= 8;
        nMsgLen += *pMsg++;

        nParsed += 4;

        if ((nParsed + nMsgLen) > nMsgSize)
        {
            return SSL_ERROR_PARSE;
        }

        nParseSize = nMsgLen;
        switch (cMsgType)
        {
        case MSG_HELLO_REQUEST:
            break;

        case MSG_CLIENT_HELLO:
            nParseSize = ParseClientHello(pSSL, pMsg, nMsgLen);
            break;

        case MSG_SERVER_HELLO:
            nParseSize = ParseServerHello(pSSL, pMsg, nMsgLen);
            break;

        case MSG_CERTIFICATE:
            nParseSize = ParseCertificateMsg(pSSL, pMsg, nMsgLen);
            break;

        case MSG_SERVER_KEY_EXCHANGE:
            break;

        case MSG_CERTIFICATE_REQUEST:
            break;

        case MSG_SERVER_HELLO_DONE:
            nParseSize = ParseServerHelloDone(pSSL, pMsg, nMsgLen);
            break;

        case MSG_CERTIFICATE_VERIFY:
            nParseSize = ParseCertificateVerify(pSSL, pMsg, nMsgLen);
            break;

        case MSG_CLIENT_KEY_EXCHANGE:
            nParseSize = ParseClientKeyExchange(pSSL, pMsg, nMsgLen);
            break;

        case MSG_FINISHED:
            if (0 == VerifyClientFinished(pSSL, pMsg, nMsgLen))
            {
                //ClientFinishedMessage verified OK.
                if (pSSL->eState == SSLSTATE_CLIENT_FINISH1)
                {
                    pSSL->eState = SSLSTATE_SERVER_FINISH2;
                }
                else if (pSSL->eState == SSLSTATE_CLIENT_FINISH2)
                {
                    pSSL->eState = SSLSTATE_HANDSHAKE_DONE;
                }
                else if (pSSL->eState != SSLSTATE_CONNECTED)
                {
                    //We are in the wrong state to have received
                    //the ServerFinished message. What to do?
                    assert(0);
                    SSLSTATE_HANDSHAKE_DONE;
                }
            }
            else
            {
                //The serverFinished message mismatch. What to do?
                assert(0);
            }
            if (pSSL->nTemp2 == MSG_CERTIFICATE_REQUEST)
            {
                //We requested client certificate but the client did not go all the way through
                pSSL->eState = SSLSTATE_CERTIFICATE_REJECTED;
            }
            break;
        }

        assert(nParseSize == nMsgLen);

        pMsg     += nParseSize;
        nParsed  += nParseSize;

        //Hash the handshake content. Hash every handshake message. NOTE
        //for the purpose of calculating FinishedMessage, the HandshakeHash
        //does not include the FinishedMessage itself. So we have to do
        //the HandshakeHash right after we parse the handshake message.
        DigestMsg(pSSL, pHashData, (uint)(pMsg-pHashData));
    }

    assert(nParsed == nMsgSize);   // We should have parsed exactly all the bytes.

    return nParsed;
}


/******************************************************************************
* Function:     VerifyClientFinished
*
* Description:  Verify the client finish message is correct
*
* Returns:      Zero if message is correct.
******************************************************************************/
uint VerifyClientFinished
(
    SSL*            pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uchar   nMsgLen;
    uchar   clientFinishedMsg[MD5_SIZE+SHA1_SIZE];

    nMsgLen = CreateFinishedMsg(
        pSSL,
        ISCLIENT,   //This message came from client.
        clientFinishedMsg,
        sizeof(clientFinishedMsg)
        );

    assert(nMsgLen == nMsgSize);

    return memcmp(pMsg, clientFinishedMsg, (nMsgLen|nMsgSize));
}


/******************************************************************************
* Function:     CreateServerMsg
*
* Description:  Create a generic server message
*
* Returns:      Bytes of message constructed.
******************************************************************************/
uint CreateServerMsg
(
    SSL*        pSSL,
    uchar   cContentType,
    const uchar* pData,
    uint   nDataSize
)
{
    uint    nLen, nMacSize, nEncryptSize;
    uchar*  pMsgBuff = &(pSSL->netoutMsg[pSSL->nNetOutSize]);
    uchar*  pMsg = pMsgBuff;
    uchar*  pEncryptData;

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
        assert(0);
        nMacSize = MD5_SIZE;
        break;
    }

    *pMsg++ = cContentType;

    *pMsg++ = pSSL->preMasterSecret[0]; //SSL_VERSION_MAJOR;
    *pMsg++ = (SSL_VERSION_MINOR<pSSL->preMasterSecret[1])?SSL_VERSION_MINOR:pSSL->preMasterSecret[1];

    nEncryptSize = nDataSize + nMacSize;

    *pMsg++ = (uchar)(nEncryptSize>>8);
    *pMsg++ = (uchar)(nEncryptSize>>0);

    //Starting here is data that needs to be encrypted.
    pEncryptData = pMsg;
    nEncryptSize -= nMacSize;   //We will add it back later

    memcpy(pMsg, pData, nDataSize);
    pMsg += nEncryptSize;

    //Now calculate the MAC of the message
    pMsg += CalculateMAC(
        pSSL,
        ISSERVER,   //This message is from Server.
        pMsg,
        (*pMsgBuff),
        pEncryptData,
        nEncryptSize
        );

    nEncryptSize += nMacSize;   //Now we added the size of MAC back

    //Now we do the encryption, after the MAC is appended.
    RC4Code(&(pSSL->serverCipher), pEncryptData, nEncryptSize);

    nLen = pMsg - pMsgBuff;

    assert((uint)(pMsg - pEncryptData) == nEncryptSize);

    pSSL->nNetOutSize += nLen;

    return nLen;
}


/******************************************************************************
* Function:     CreateAlertMsg
*
* Description:  Create a server alert message.
*
* Returns:      Bytes of message constructed.
******************************************************************************/
uint CreateAlertMsg
(
    SSL*    pSSL,
    uchar   cCategory,
    uchar   cType
)
{
    uchar       msg[2];

    msg[0] = cCategory;
    msg[1] = cType;

    return CreateServerMsg(pSSL, CONTENT_ALERT, msg, sizeof(msg));
}
