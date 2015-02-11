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
*  File Name:       ssl.c
*
*  Description:     Implementation of SSL 3.0 and TLS 1.0 client.
*
*                   I initially used test case data from
*                       http://wp.netscape.com/ssl3/traces/
*                   The old netscape web page is no longer available but
*                   the same trace data can now be found at:
*                       http://www.mozilla.org/projects/security/pki/nss/ssl/traces/
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
#include <assert.h>
#include <stdint.h>

#include "ssl.h"
#include "cipher.h"

#include "ssl_int.h"

#include "clientMsg.h"
#include "msecret.h"
#include "hmac.h"
#include "cert.h"

#ifndef FALSE
#define TRUE    1
#define FALSE   0
#endif //FALSE

#define CONTENT_HEADER_LEN      5
#define SSL_OVERHEAD            (CONTENT_HEADER_LEN+MD5_SIZE)

//Static function protocol declarations

static void* MemAlloc(uint nSize);
static void MemFree(void* pData);
static uint CreateNetMsg(SSL* pSSL, uchar cContentType, const uchar* pData, uint nDataSize);


//Global data declarations
static uint nSSLInstanceCount = 0;
SSL_MALLOC  gfMalloc = NULL; //Memory allocation function. Must NOT be NULL.
SSL_FREE    gfFree   = NULL; //Memory deallocate function. Must NOT be NULL.
SSL_RANDOM  gfRandom = NULL; //Pseudo Random Number Generator function. Must NOT be NULL.

const CIPHERSET* gpCipherSet = NULL;

uint gSvrMsgSize = 0 ;
uint gAppMsgSize = 0 ;

//Used in SSL 3.0
static const uchar SENDER_CLIENT[] = "CLNT";
static const uchar SENDER_SERVER[] = "SRVR";

//Used in SSL 3.1 / TLS 1.0 and after.
static const char   CLIENT_LABEL[] = "client finished";
static const char   SERVER_LABEL[] = "server finished";


const uchar PAD1[PADSIZE_MD5] = //Size is MAX(PADSIZE_MD5, PADSIZE_SHA)
{
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
};

const uchar PAD2[PADSIZE_MD5] = //Size is MAX(PADSIZE_MD5, PADSIZE_SHA)
{
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C
};


//****  Function implementations  *********************************************

static void SSL_Reset(HSSL  pSSL);


/******************************************************************************
* Function:     SSL_Initialize
*
* Description:  Initialize SSL module. This call must preceeds any other SSL
*               calls. Application optionally provides memory allocation,
*               memory free, and random number generator functions.
*
* Returns:      SSL_OK if no error.
******************************************************************************/
SSL_RESULT SSL_Initialize
(
    SSL_MALLOC      pMallocFunc,
    SSL_FREE        pFreeFunc,
    SSL_RANDOM      pRandomFunc,
    const CIPHERSET* pCipherSet,
    uint            nSvrMsgSize,
    uint            nAppMsgSize
)
{
    gfMalloc    = pMallocFunc;
    gfFree      = pFreeFunc;
    gfRandom    = pRandomFunc;
    gpCipherSet = pCipherSet;

    StartCerts(pMallocFunc, pFreeFunc, pCipherSet);

    if( nSvrMsgSize > 0 )
    {
        gSvrMsgSize = nSvrMsgSize ;
    }

    if( nAppMsgSize > 0 )
    {
        gAppMsgSize = nAppMsgSize ;
    }

    return SSL_OK;
}


/******************************************************************************
* Function:     SSL_AddRootCertificate
*
* Description:  This function is used to add trusted root certificates.
*               Selected *.cer files dumped from the InternetExplorer
*               root certificates are OK, as long as the associated entities
*               can continue to be trusted.
*
* Returns:      SSL_OK if no error.
******************************************************************************/
SSL_RESULT SSL_AddRootCertificate
(
    const uchar*    pCertData,
    uint            nLen,
    uint            nUnixTime
)
{
    CERT_STATUS     eStatus = CS_ROOT;
    uint    nLen2;
    CERT*           pCert = NULL;

    pCert = CreateCert(eStatus, nUnixTime);

    nLen2 = ParseCert(pCert, pCertData, nLen);

    if (nLen2 != nLen)
    {
        DestroyCert(pCert);
        return SSL_ERROR_CERTIFICATE_BAD;
    }

    eStatus = AuthenticateCert(pCert, NULL);

    if (NULL == InsertCert(pCert, NULL))
    {
        DestroyCert(pCert);
        return SSL_ERROR_CERTIFICATE_EXISTS;
    }

    return SSL_OK;
}

/******************************************************************************
* Function:     SSL_AddCRL
*
* Description:  This function is used to add CRL (Certificate RevocationList).
*               Application should obtain current (up to date) CRLs from the
*               internet. One source is:
*                   http://www.geotrust.com/resources/crls/index.htm
*
* Returns:      SSL_OK if no error.
******************************************************************************/
SSL_RESULT SSL_AddCRL(uchar* pCRL, uint nLen)
{
    // TO be implemented.
    return SSL_RESULT_NOT_APPLY;
}


void SSL_Reset(HSSL pSSL)
{
    if (NULL == pSSL) return;

    pSSL->nSessionIDLen = 0;
    pSSL->serverMsgLen = 0;
    pSSL->serverMsgOff = 0;
    pSSL->nNetOutSize = 0;
    pSSL->nAppOutSize = 0;

    pSSL->pTemp = NULL;
    pSSL->nTemp1 = 0;
    pSSL->nTemp2 = 0;
    pSSL->eLastError = SSL_OK;

    if (pSSL->pServerCert != NULL)
    {
        DeleteCert(pSSL->pServerCert, &(pSSL->pMidCerts));
        DestroyCert(pSSL->pServerCert);
        pSSL->pServerCert = NULL;
    }

    if (pSSL->pMidCerts != NULL)
    {
        CleanupCerts(&(pSSL->pMidCerts));
    }

    pSSL->eState = SSLSTATE_INITIALIZED;
}


/******************************************************************************
* Function:     SSL_Create
*
* Description:  Create an instance of HSSL to be used in a HTTPS connection session.
*
* Returns:      SSL_OK if successful.
******************************************************************************/
SSL_RESULT SSL_Create
(
    HSSL*           pHSSL,
    CERTKEY_INFO*   pCertKey
)
{
    SSL*    pSSL;

    pSSL = gfMalloc(sizeof(*pSSL));
    *pHSSL = NULL;
    if (NULL != pSSL)
    {
        memset(pSSL, 0, sizeof(*pSSL));

        pSSL->pCertKey = pCertKey;

        pSSL->eState = SSLSTATE_INITIALIZED;
        nSSLInstanceCount ++;

        pSSL->serverMsg = gfMalloc( gSvrMsgSize );
        if (gAppMsgSize > 0)
        {
        pSSL->appoutMsg = gfMalloc( gAppMsgSize );
        }

        if ((NULL != pSSL->serverMsg) && ((NULL != pSSL->appoutMsg) || (gAppMsgSize <= 0)))
        {
            pSSL->eLastError = SSL_OK;
            *pHSSL = pSSL;
            SSL_Reset(pSSL);
            return SSL_OK;
        }
        else
        {
            SSL_Destroy(pSSL);
            pSSL = NULL;
        }
    }

    return SSL_ERROR_MEMORY;
}


/******************************************************************************
* Function:     SSL_Destroy
*
* Description:  Destroy an instance of HSSL. The instance should no longer be used.
*
* Returns:      SSL_OK
******************************************************************************/
SSL_RESULT SSL_Destroy(HSSL pSSL)
{
    if (NULL != pSSL)
    {
        if (pSSL->pServerCert)
        {
            CERT*   pCert;

            pCert = DeleteCert(pSSL->pServerCert, &(pSSL->pMidCerts));
            DestroyCert(pSSL->pServerCert);
        }

        if (pSSL->pMidCerts != NULL)
        {
            CleanupCerts(&(pSSL->pMidCerts));
        }

        if ((NULL != pSSL->appoutMsg) && (gAppMsgSize != 0))
        {
            gfFree( pSSL->appoutMsg );
            pSSL->appoutMsg = NULL;
        }
        if (NULL != pSSL->serverMsg)
        {
            gfFree( pSSL->serverMsg );
            pSSL->serverMsg = NULL;
        }

        gfFree(pSSL);

        nSSLInstanceCount--;
        if (nSSLInstanceCount == 0)
        {
            //We no longer have any instance of SSL. What to do?
        }
    }

    return SSL_OK;
}


/******************************************************************************
* Function:     SSL_Process
*
* Description:  The one big callback function that handles everything.
*
* Returns:      
******************************************************************************/
//The filtering function that carries out all SSL operations.
SSL_RESULT SSL_Process
(
    SSL_PARAMS* pParam,
    HSSL        pSSL
)
{
    uint nAppOutBuffSize = gAppMsgSize;

    if ((NULL == pSSL) || (NULL == pParam))
    {
        return SSL_ERROR_GENERIC;
    }

    pSSL->eLastError = SSL_OK;

    //Reset return parameters so we do not unintentionally return something.
    pParam->pNetOutData = NULL;
    pParam->nNetOutSize = 0;

    if (nAppOutBuffSize == 0)
    {
        pSSL->appoutMsg = pParam->pAppOutData;
        nAppOutBuffSize = pParam->nAppOutSize;
    }
    pParam->pAppOutData = NULL;
    pParam->nAppOutSize = 0;

    pSSL->nNetOutSize = 0;
    pSSL->nAppOutSize = 0;

    //First update our time. The time is a UINT32 seconds since
    //the EPOCH, 00:00AM 01/01/1970 UTC.
    pSSL->nCurrentTime = pParam->nUnixTime;

    //Second do we have a state change?
    if (pParam->eState != pSSL->eState)
    {
        pSSL->eState = pParam->eState;
        switch (pSSL->eState)
        {
        case SSLSTATE_RESET:
            SSL_Reset(pSSL);
            pSSL->eState = SSLSTATE_INITIALIZED;
            break;

        case SSLSTATE_TCPCONNECTED:
            {
                pSSL->nStartTime = pSSL->nCurrentTime;
                pSSL->eClientCipher = CIPHER_NOTSET;
                pSSL->eServerCipher = CIPHER_NOTSET;
                pSSL->serverMsgOff = 0;
                pSSL->serverMsgLen = 0;
                pSSL->eState = SSLSTATE_HANDSHAKE_BEGIN;
            }
            break;

        case SSLSTATE_DISCONNECT:
            {
                //We were told by the App to initiate disconnect sequence.
                //This is done by sending a Close Alert to the server, then
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
    while ((NULL != pParam->pNetInData) && (pParam->nNetInSize > 0))
    {
        uint    nParse, nChunk = pParam->nNetInSize;

        if (nAppOutBuffSize == 0)
        {
            //Neither Application provided the AppOut buffer, nor was it allocated
            //internally. So we share the serverMsg buffer. Nothing to do here.
        }
        else
        {
            if (nChunk > ((nAppOutBuffSize)>>1))
            {
                nChunk = ((nAppOutBuffSize)>>1);
            }

            //Do we have big enough App Out buffer to parse the message
            if ((nChunk + pSSL->nAppOutSize) > nAppOutBuffSize)
            {
                if ((SSL_OVERHEAD + pSSL->nAppOutSize) < nAppOutBuffSize)
                {
                    nChunk = nAppOutBuffSize - pSSL->nAppOutSize;
                }
                else
                {
                    //Buffer full. Can not parse anything.
                    nChunk = 0;
                    pSSL->eLastError = SSL_ERROR_BUFFER_FULL;
                    return pSSL->eLastError;
                }
            }
        }

        nParse = ParseServerMsg(
            pSSL, 
            pParam->pNetInData,
            nChunk
            );

        pParam->pNetInData += nParse;
        pParam->nNetInSize -= nParse;

        //Any error parsing server message?
        if (pSSL->eLastError != SSL_OK)
        {
            return pSSL->eLastError;
        }
    }

    //Fourth do we have any state change because of server message parsing?
    do
    {
        pParam->eState = pSSL->eState;
        switch (pSSL->eState)
        {
        case SSLSTATE_HANDSHAKE_BEGIN:
            //We create a ClientHello message and ask App to send it.
            pSSL->eState = SSLSTATE_CLIENT_HELLO;
            pSSL->nNetOutSize += CreateClientHelloMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            //We now wait for a ServerHello message.
            pSSL->eState = SSLSTATE_SERVER_HELLO;
            break;

        case SSLSTATE_CERTIFICATE_REQUEST:
            pParam->eState = pSSL->eState = SSLSTATE_CERTIFICATE_REQUESTING;
            break;

        case SSLSTATE_CERTIFICATE_REQUESTING:
            pSSL->eState = SSLSTATE_CERTIFICATE_NOTGIVEN;
            break;

        case SSLSTATE_CERTIFICATE_NOTGIVEN:
            pSSL->eState = SSLSTATE_ABORTING;
            break;

        case SSLSTATE_CERTIFICATE_SUPPLIED:
            //OK App gives up the client certificate.
            //Take the client certificate that the application gives us here.
            //Then do appropriate processing here.
            pSSL->pTemp  = (uchar*)pParam->nInXData.ptr; //Only place this is set.
            pSSL->eState = SSLSTATE_CERTIFICATE_VERIFY;
            break;

        case SSLSTATE_CERTIFICATE_VERIFY:
            {
                //Verify server certificate.
                CERT_STATUS eStatus;

                eStatus = AuthenticateCert(pSSL->pServerCert, &(pSSL->pMidCerts));

                //Give the HCERT to let App do something with it.
                pParam->nOutXData.ptr = (void*)pSSL->pServerCert;

                //Please note here. The certificate may or may not be verified,
                //depends on eStatus. That information is passed to application
                //using pParam->nOutXData. So upon seeing the state changing to
                //SSLSTATE_CERTIFICATE_VERIFIED, the application should be able
                //to look at the returned pParam->nOutXData, and decide what to
                //do next if the verify status does not look good. By default it
                //just continues on to SSLSTATE_CLIENT_KEYEXCHANGE, if no action
                //is taken by application.

                if ((eStatus & (CS_OK | CS_VERIFIED)) == (CS_OK | CS_VERIFIED))
                {
                    //Certificate is OK and can be trusted.
                    pParam->eState = pSSL->eState = SSLSTATE_CERTIFICATE_VERIFIED;
                }
                else
                {
                    //Certificate questionable. Prompt the application to decide
                    //either to goto
                    //      SSLSTATE_CERTIFICATE_ACCEPTED
                    //or to goto
                    //      SSLSTATE_CERTIFICATE_REJECTED
                    //Application should check pParam->nOutXData to decide.
                    pParam->eState = pSSL->eState = SSLSTATE_CERTIFICATE_ACCEPTING;
                }
            }
            break;

        case SSLSTATE_CERTIFICATE_VERIFIED:
            //Certificate OK, valid and trusted. So go ahead.
            pSSL->eState = SSLSTATE_CLIENT_KEYEXCHANGE;
            if (pSSL->pTemp != NULL)
            {
                //If we are to supply client certificate, then do it first.
                pSSL->eState = SSLSTATE_CLIENT_CERTIFICATE;
            }
            break;

        case SSLSTATE_CERTIFICATE_ACCEPTED:
            //Certificate may be questionable. But App accepted it any way.
            pSSL->eState = SSLSTATE_CLIENT_KEYEXCHANGE;
            if (pSSL->pTemp != NULL)
            {
                //If we are to supply client certificate, then do it first.
                pSSL->eState = SSLSTATE_CLIENT_CERTIFICATE;
            }
            break;

        case SSLSTATE_CERTIFICATE_ACCEPTING:
            //The application undeciding on this one. So we do the default and
            //prepare to disconnect the questionable connection.
            //Fall through to SSLSTATE_CERTIFICATE_REJECTED as default.
        case SSLSTATE_CERTIFICATE_REJECTED:
            pSSL->eState = SSLSTATE_ABORTING;
            break;

        case SSLSTATE_CLIENT_CERTIFICATE:
            //Same as SSLSTATE_CLIENT_KEYEXCHANGE but with extra messages, depending on pSSL->pTemp,
            //namely the client certificate message and client certificate verify message.
            pSSL->nNetOutSize += CreateClientKeyExchangeMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            pSSL->eState = SSLSTATE_CLIENT_FINISH1;
            break;

        case SSLSTATE_CLIENT_KEYEXCHANGE:
            pSSL->nNetOutSize += CreateClientKeyExchangeMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            pSSL->eState = SSLSTATE_CLIENT_FINISH1;
            break;

        case SSLSTATE_CLIENT_FINISH1:
            //First send the client ChangeCipherSpec message.
            pSSL->nNetOutSize += CreateChangeCipherSpecMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            //Then send the ClientFinished message.
            pSSL->nNetOutSize += CreateClientFinishedMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            if (pSSL->eServerCipher == CIPHER_NOTSET)
            {
                pSSL->eState = SSLSTATE_SERVER_FINISH2;
            }
            else
            {
                pSSL->eState = SSLSTATE_HANDSHAKE_DONE;
            }
            break;

        case SSLSTATE_CLIENT_FINISH2:
            //First send the client ChangeCipherSpec message.
            pSSL->nNetOutSize += CreateChangeCipherSpecMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            //Then send the ClientFinished message.
            pSSL->nNetOutSize += CreateClientFinishedMsg(
                pSSL,
                &(pSSL->netoutMsg[pSSL->nNetOutSize]),
                (sizeof(pSSL->netoutMsg) - pSSL->nNetOutSize)
                );
            pSSL->eState = SSLSTATE_HANDSHAKE_DONE;
            break;

        case SSLSTATE_HANDSHAKE_DONE:
            pSSL->eState = SSLSTATE_CONNECTED;
            break;

        case SSLSTATE_CONNECTED:
            //We are fully connected. Hope to stay that way indefinitely.
            break;

        case SSLSTATE_ABORT:
            //There is an internal error processing the incoming message, so bail out
            pParam->eState = pSSL->eState = SSLSTATE_ABORTING;
            break;

        case SSLSTATE_ABORTING:
            //TODO: May need to send an abort message to the server here.
            //After the abort message is sent. Set the below state. Application then
            //should disconnect the TCP, and change state to SSLSTATE_DISCONNECTED.
            pSSL->eState = SSLSTATE_ABORTED;
            break;

        default:
            break;
        }
    } while (pParam->eState != pSSL->eState);


    //Fifth do we have any application data that needs to be sent out?
    if ((pParam->nAppInSize > 0) && (NULL != pParam->pAppInData))
    {
        uint    nMsgSize;

        //if (pSSL->eState != SSLSTATE_CONNECTED)
        if (pSSL->eClientCipher == CIPHER_NOTSET)
        {
            return SSL_ERROR_NOTREADY;
        }

        nMsgSize = CreateNetMsg(
            pSSL,
            CONTENT_APPLICATION_DATA,
            pParam->pAppInData,
            pParam->nAppInSize
            );

        if (nMsgSize > 0)
        {
            //The outgoing message is processed successfully
            pParam->nAppInSize = 0;
        }
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

    if (gAppMsgSize == 0)
    {
        //The buffer was Application provided, so dis-own it.
        pSSL->appoutMsg = NULL;
        pSSL->nAppOutSize = 0;
    }

    return SSL_OK;
}


/******************************************************************************
* Function:     SSL_Cleanup
*
* Description:  The cleanup function that should be the last SSL function to be called.
*
* Returns:      SSL_OK.
******************************************************************************/
SSL_RESULT SSL_Cleanup()
{
    CleanupCerts(NULL);

    gfRandom = NULL;
    gfFree   = NULL;
    gfMalloc = NULL;
    gSvrMsgSize = 0;
    gAppMsgSize = 0;

    return SSL_OK;
}


/******************************************************************************
* Function:     DigestInit
*
* Description:  Initialize the SSL message digests.
*
* Returns:      None
******************************************************************************/
void DigestInit
(
    SSL*    pSSL
)
{
    gpCipherSet->md5.Init(&(pSSL->md5Ctx), gpCipherSet->md5.pIData);
    gpCipherSet->sha1.Init(&(pSSL->sha1Ctx), gpCipherSet->sha1.pIData);
}


/******************************************************************************
* Function:     DigestMsg
*
* Description:  Calculate accumulated SSL message digest
*
* Returns:      None
******************************************************************************/
void DigestMsg
(
    SSL*            pSSL,
    const uchar*    pMsg,
    uint            nMsgLen
)
{
    gpCipherSet->md5.Input(&(pSSL->md5Ctx), pMsg, nMsgLen);
    gpCipherSet->sha1.Input(&(pSSL->sha1Ctx), pMsg, nMsgLen);
}


/******************************************************************************
* Function:     DigestInit1
*
* Description:  Initialize message digest context in pBlock.
*
* Returns:      None.
******************************************************************************/
void DigestInit1
(
    EBLOCK*     pBlock
)
{
    gpCipherSet->md5.Init(&(pBlock->md5Hash), gpCipherSet->md5.pIData);
    gpCipherSet->sha1.Init(&(pBlock->sha1Hash), gpCipherSet->sha1.pIData);
}


/******************************************************************************
* Function:     DigestInit2
*
* Description:  Transfer message digest context to pBlock.
*
* Returns:      None.
******************************************************************************/
void DigestInit2
(
    const SSL*  pSSL,
    EBLOCK*     pBlock
)
{
    pBlock->md5Hash  = pSSL->md5Ctx;
    pBlock->sha1Hash = pSSL->sha1Ctx;
}


/******************************************************************************
* Function:     DigestBlock
*
* Description:  Calculate the digest of previous digest results.
*
* Returns:      None.
******************************************************************************/
void DigestBlock(EBLOCK* pBlock)
{
    gpCipherSet->md5.Input(&(pBlock->md5Hash),  pBlock->md5Digest,  MD5_SIZE);
    gpCipherSet->sha1.Input(&(pBlock->sha1Hash), pBlock->sha1Digest, SHA1_SIZE);
}


/******************************************************************************
* Function:     DigestMsg2
*
* Description:  Calculate message digest on pBlock.
*
* Returns:      None.
******************************************************************************/
void DigestMsg2
(
    EBLOCK*         pBlock,
    const uchar*    pMsg,
    uint            nMsgLen
)
{
    gpCipherSet->md5.Input(&(pBlock->md5Hash), pMsg, nMsgLen);
    gpCipherSet->sha1.Input(&(pBlock->sha1Hash), pMsg, nMsgLen);
}


/******************************************************************************
* Function:     DigestPad2
*
* Description:  Digest pad bytes. Note number of bytes digested is different
*               for MD5 and SHA1
*
* Returns:      None
******************************************************************************/
void DigestPad2
(
    EBLOCK*         pBlock,
    const uchar*    pPad
)
{
    gpCipherSet->md5.Input(&(pBlock->md5Hash), pPad, PADSIZE_MD5);
    gpCipherSet->sha1.Input(&(pBlock->sha1Hash), pPad, PADSIZE_SHA);
}


/******************************************************************************
* Function:     DigestOut2
*
* Description:  Finalize and output the digests in pBlock
*
* Returns:      
******************************************************************************/
void DigestOut2(EBLOCK* pBlock)
{
    gpCipherSet->md5.Digest(&(pBlock->md5Hash), pBlock->md5Digest);
    gpCipherSet->sha1.Digest(&(pBlock->sha1Hash), pBlock->sha1Digest);
}


/******************************************************************************
* Function:     ParseServerMsg
*
* Description:  Parse the server SSL message
*
* Returns:      Number of bytes copied into serverMsg buffer.
******************************************************************************/
uint ParseServerMsg
(
    SSL*                    pSSL,
    const uchar*    pServerMsg,
    uint            nMsgLen
)
{
    uint    nCopied = 0;
    uint    nParsed = 0;
    uchar*  pMsg;
    int             nCopySize = 0;
    uchar   cContentType, verMajor, verMinor;
    uint    nContentSize = 0, nMsgSize;

    pSSL->eLastError = SSL_OK;

    while (((nMsgLen > 0) || (nParsed > 0)) && (pSSL->eLastError == SSL_OK))
    {
        // First re-align any remainder server message to the beginning
        // of buffer pSSL->serverMsg, if there is unaligned message
        // data from previous parsing. But do it only when we are ready
        // to copy more data from input.
        if ((pSSL->serverMsgOff > 0) && (nMsgLen > 0))
        {
            if ((pSSL->nAppOutSize > 0) && (gAppMsgSize == 0))
            {
                //Can not memmove because we share a buffer. So can not reset
                //pSSL->serverMsgOff to 0, even if pSSL->serverMsgLen is 0.
            }
            else
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
        }

        // Second copy what we can from the input buffer into pSSL->serverMsg buffer.
        nCopySize = gSvrMsgSize - pSSL->serverMsgLen - pSSL->serverMsgOff;
        if (nCopySize > (int)nMsgLen)
        {
            nCopySize = nMsgLen;
        }

        if (nCopySize > 0)
        {
            memcpy(pSSL->serverMsg+pSSL->serverMsgOff+pSSL->serverMsgLen, pServerMsg, nCopySize);
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
        cContentType = *pMsg++;
        verMajor     = *pMsg++;
        verMinor     = *pMsg++;
        nContentSize = *pMsg++;
        nContentSize <<= 8;
        nContentSize += *pMsg++;

        if ((verMajor == SSL_VERSION_MAJOR) && (verMinor <= SSL_VERSION_MINOR))
        {
            // We are OK.
        }
        else
        {
            pSSL->eLastError = SSL_ERROR_PARSE;
            break;
        }

        if (pSSL->serverMsgLen < CONTENT_HEADER_LEN + nContentSize)
        {
            // We do not have the complete message yet.
            continue;
        }

        nMsgSize = nContentSize;    //nMsgSize is nContentSize minus the MAC

        //If the cipher has been turned on already. Then we need to decrypt
        switch (pSSL->eServerCipher)
        {
        case CIPHER_NOTSET:
            //No need to decrypt.
            break;
        case CIPHER_RSA_RC4_40_MD5:
        case CIPHER_RSA_RC4_128_MD5:
        case CIPHER_RSA_RC4_128_SHA:
            RC4Code(&(pSSL->serverCipher), pMsg, nContentSize);
            if (0 == VerifyServerMAC(pSSL, cContentType, pMsg, &nMsgSize))
            {
                //We are OK.
            }
            else
            {
                //Corrupted message. What to do?
                pSSL->eLastError = SSL_ERROR_PARSE;
                assert(0);
            }
            break;
        default:
            //Unsupported cipher.
            pSSL->eLastError = SSL_ERROR_PARSE;
            assert(0);
            break;
        }

        if (pSSL->eLastError == SSL_OK) //Then do the switch
        switch (cContentType)
        {
        case CONTENT_CHANGECIPHERSPEC:
            ParseChangeCipherSpec(pSSL, pMsg, nMsgSize);
            break;
        case CONTENT_ALERT:
            ParseAlertMsg(pSSL, pMsg, nMsgSize);
            break;
        case CONTENT_HANDSHAKE:
            ParseHandshake(pSSL, pMsg, nMsgSize);
            break;
        case CONTENT_APPLICATION_DATA:
            ParseAppData(pSSL, pMsg, nMsgSize);
            break;
        default:
            break;
        }

        nParsed = CONTENT_HEADER_LEN + nContentSize;
        pSSL->serverMsgOff += nParsed;
        pSSL->serverMsgLen -= nParsed;
    }

    // Just for debugging
    if( pSSL->serverMsgLen >= gSvrMsgSize )
    {
        // Buffer not big enough. Need to increase pSSL->serverMsg.
        pSSL->eLastError = SSL_ERROR_PARSE;
        assert(0);
    }

    return nCopied;
}


/******************************************************************************
* Function:     ParseHandshake
*
* Description:  Parse an incoming network message that belongs to CONTENT_HANDSHAKE
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseHandshake
(
    SSL*                    pSSL,
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
            //Server request a hello message again, so re-start the handshake.
            pSSL->eState = SSLSTATE_HANDSHAKE_BEGIN;
            break;

        case MSG_CLIENT_HELLO:
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
            nParseSize = ParseCertificateRequest(pSSL, pMsg, nMsgLen);
            break;

        case MSG_SERVER_HELLO_DONE:
            nParseSize = ParseServerHelloDone(pSSL, pMsg, nMsgLen);
            break;

        case MSG_CERTIFICATE_VERIFY:
            break;

        case MSG_CLIENT_KEY_EXCHANGE:
            break;

        case MSG_FINISHED:
            if (0 == VerifyServerFinished(pSSL, pMsg, nMsgLen))
            {
                //ServerFinishedMessage verified OK.
                if (pSSL->eState == SSLSTATE_SERVER_FINISH1)
                {
                    pSSL->eState = SSLSTATE_CLIENT_FINISH2;
                }
                else if (pSSL->eState == SSLSTATE_SERVER_FINISH2)
                {
                    pSSL->eState = SSLSTATE_HANDSHAKE_DONE;
                }
                else
                {
                    //We are in the wrong state to have received
                    //the ServerFinished message. What to do?
                    assert(0);
                }
            }
            else
            {
                //The serverFinished message mismatch. What to do?
                assert(0);
            }
            break;
        }

        pMsg     += nParseSize;
        nParsed  += nParseSize;

        if (cMsgType == MSG_HELLO_REQUEST)
        {
            //http://www.ietf.org/rfc/rfc2246.txt
            if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
                (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
            {
                //Note in RFC2246 it suggest that hello request message is not included in the handshake hask.
                //So probably I should just do a continue here. But not verified yet
                //so I comment out the continue here.
                //See http://www.ietf.org/rfc/rfc2246.txt

                //continue;
            }
        }

        //Hash the handshake content. Hash every handshake message. NOTE
        //for the purpose of calculating FinishedMessage, the HandshakeHash
        //does not include the FinishedMessage itself. So we have to do
        //the HandshakeHash right after we parse the handshake message.
        DigestMsg(pSSL, pHashData, (uint)(pMsg-pHashData));
    }

    return nParsed;
}


/******************************************************************************
* Function:     ParseChangeCipherSpec
*
* Description:  Parse the Change Cipher Spec message. After this point all
*               messages are encrypted.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseChangeCipherSpec
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
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
        (CIPHER_RSA_RC4_128_MD5 == pSSL->eServerCipher) ||
        (CIPHER_RSA_RC4_128_SHA == pSSL->eServerCipher) )
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
    }

    //Reset the server write sequence number.
    pSSL->serverSequenceL = 0;
    pSSL->serverSequenceH = 0;

    return nMsgSize;
}


/******************************************************************************
* Function:     ParseServerHello
*
* Description:  Parse the server hello message.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseServerHello
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uint    nParsed = 0;
    uint    nSessionIDLen;
    uint    nPendingCipher;
    uint    nCompression;
    uchar   verMajor, verMinor;

    verMajor = *pMsg++;
    verMinor = *pMsg++;
    nParsed  += 2;

    pSSL->preMasterSecret[0] = SSL_VERSION_MAJOR;
    pSSL->preMasterSecret[1] = (verMinor<SSL_VERSION_MINOR)?verMinor:SSL_VERSION_MINOR;

    // First in server hello msg, two bytes of server version.
    // Do we require the server to be version 3.0, no more, no less?

    // Next 32 bytes (SERVER_RANDOM_SIZE) of ServerRandom.
    memcpy(pSSL->serverRandom, pMsg, SERVER_RANDOM_SIZE);
    pMsg += SERVER_RANDOM_SIZE;
    nParsed  += SERVER_RANDOM_SIZE;

    // Next byte tells session ID length
    nSessionIDLen = (uint)(*pMsg++);
    nParsed  ++;

    if (nSessionIDLen > 0)
    {
        if ((pSSL->nSessionIDLen == nSessionIDLen) &&
            (0 == memcmp(pSSL->sessionID, pMsg, nSessionIDLen)) )
        {
            //No need to do ClientKeyExchange. We re-use the old
            //Pre-Master Secret from the last connection session.
            pSSL->eState = SSLSTATE_SERVER_FINISH1;
        }
        else
        {
            memcpy(pSSL->sessionID, pMsg, nSessionIDLen);
        }
        pMsg += nSessionIDLen;
        nParsed  += nSessionIDLen;
    }
    pSSL->nSessionIDLen = nSessionIDLen;

    // Next two bytes is the pending ciphers.
    nPendingCipher = *pMsg++;
    nPendingCipher <<= 8;
    nPendingCipher += *pMsg++;

    //The final byte is Compression. We support only 0, no compression.
    nCompression = *pMsg++;

    pSSL->ePendingCipher = nPendingCipher;

    nParsed  += 3;

    if (nParsed < nMsgSize)
    {
        //There are extentions to the message
        uint nExtSize0 = 0;
        
        nExtSize0  = *pMsg++;
        nExtSize0 <<= 8;
        nExtSize0 += *pMsg++;
        nParsed   += 2;

        //Parse the message extention here.
        if (nParsed + nExtSize0 <= nMsgSize)
        {
            uint    nExtType = 0;
            uint    nExtSize = 0;
            uint    bAbort = FALSE;

            nExtType  = *pMsg++;
            nExtType <<= 8;
            nExtType += *pMsg++;

            if (nExtType == ((MSG_EXTENTION<<8) | MSG_EXTENTION_RENEGOTIATION))
            {
                nExtSize  = *pMsg++;
                nExtSize <<= 8;
                nExtSize += *pMsg++;

                nExtSize --;

                if (nExtSize != *pMsg++)
                {
                    //Malformed extention message.
                    bAbort = TRUE;
                }
                else if (nExtSize > 0)
                {
                    if (pSSL->eServerCipher == CIPHER_NOTSET)
                    {
                        //Not expecting a non-empty re-negotiation info message.
                        bAbort = TRUE;
                    }
                    else if (memcmp(pSSL->clientVerify, pMsg, (nExtSize>>1)))
                    {
                        bAbort = TRUE;
                    }
                    else if (memcmp(pSSL->serverVerify, pMsg+(nExtSize>>1), (nExtSize>>1)))
                    {
                        bAbort = TRUE;
                    }
                    else
                    {
                        //The expected renegotiation info message matches. So OK here.
                        bAbort = FALSE;
                    }
                    pMsg += nExtSize;
                }
                else if (pSSL->eServerCipher != CIPHER_NOTSET)
                {
                    //We do expect a non-empty re-negotiation info message.
                    bAbort = TRUE;
                }
                else
                {
                    //We expect an empty renegotiation info message. So OK here.
                    bAbort = FALSE;
                }
            }

            if (bAbort)
            {
                //Something wrong with the re-negotiation info message. Bailout.
                pSSL->eState = SSLSTATE_ABORT;
            }
        }
        else
        {
            //Something not quite right here. So just bail out.
            pSSL->eState = SSLSTATE_ABORT;
        }

        nParsed += nExtSize0;
    }

    //assert(nParsed == nMsgSize); // We should have parsed exactly all the bytes.

    return nMsgSize;
}


/******************************************************************************
* Function:     ParseServerHelloDone
*
* Description:  Parse the server hellow done message.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseServerHelloDone
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    // Not much to be parsed. Just carry out operations that is needed upon
    // the ServerHelloDone.

    //Make sure we are expecting a ServerHelloDone at this point.

    //Upon receiving a ServerHelloDone, we should verify Server Certificate,
    //Generate the client key exchange message and send out.
    pSSL->pTemp = NULL; //We set it that we have no client certificate.
    if (pSSL->eState == SSLSTATE_SERVER_CERTREQUEST)
    {
        pSSL->eState = SSLSTATE_CERTIFICATE_REQUEST;
    }
    else
    {
        pSSL->eState = SSLSTATE_CERTIFICATE_VERIFY;
    }

    return nMsgSize;
}


/******************************************************************************
* Function:     VerifyServerFinished
*
* Description:  Verify that the server finished message is correctly calculated
*               thus the key exchange handshake is successful.
*
* Returns:      ZERO if no error, else there is an error.
******************************************************************************/
uint VerifyServerFinished
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uchar   serverFinishedMsg[MD5_SIZE+SHA1_SIZE];
    uint   nMsgLen;

    nMsgLen = CreateFinishedMsg(
        pSSL,
        ISSERVER,   //We are constructing a server message
        serverFinishedMsg,
        sizeof(serverFinishedMsg)
        );

    return memcmp(pMsg, serverFinishedMsg, (nMsgLen|nMsgSize));
}


/******************************************************************************
* Function:     ParseCertificateMsg
*
* Description:  Parse the certificate message and extract certificate(s).
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseCertificateMsg
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uint    nParsed = 0;
    uint    nTotalSize;
    uint    nCurrentSize;
    struct CERT*    pCert = NULL;

    // We are parsing a possible list of N certificates.

    // First 3 bytes tells us the the total size we should be parsing.
    //Not including the 3 bytes itself.
    nTotalSize  = *pMsg++;
    nTotalSize<<= 8;
    nTotalSize += *pMsg++;
    nTotalSize<<= 8;
    nTotalSize += *pMsg++;
    nParsed += 3;

    while (nParsed < nMsgSize)
    {
        uint    nCertParsed;

        //Next 3 bytes tells us the size of next certificate to be parsed.
        nCurrentSize  = *pMsg++;
        nCurrentSize<<= 8;
        nCurrentSize += *pMsg++;
        nCurrentSize<<= 8;
        nCurrentSize += *pMsg++;
        nParsed += 3;

        pCert = CreateCert(CS_UNKNOWN, pSSL->nCurrentTime);

        nCertParsed = ParseCert(pCert, pMsg, nCurrentSize);

        pMsg    += nCurrentSize;
        nParsed += nCurrentSize;

        //The very first certificate is the server certificate. Anything that follows
        //are CA certificates that need to be inserted.
        if (pSSL->pServerCert == NULL)
        {
            pSSL->pServerCert = pCert;
        }
        else if (NULL == InsertCert(pCert, &(pSSL->pMidCerts)))
        {
            //Can not insert certificate since it exists already as root.
            //So ignore the one coming from the network.
            DestroyCert(pCert);
        }
    }

    //We received server certificate so next to come is ServerHelloDone.
    pSSL->eState = SSLSTATE_SERVER_HELLO_DONE;

    return nParsed;
}


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

extern struct X509NAME gTempCA;

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


/******************************************************************************
* Function:     ParseCertificateRequest
*
* Description:  Parse the certificate request message from the server. This message
*               contains information on CAs whose certificates can be accepted.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseCertificateRequest
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uint    i, nParse, nParsed = 0;
    uint    nTotalSize;
    uint    eCipherType;
    uint    nCipherTypes = 0;

    nCipherTypes  = *pMsg++;    //Number of cipher types. Normally just two.
    nParsed ++;

    //Then a list of nCipherTypes entry of cipher types, one byte each.
    for (i=0; i<nCipherTypes; i++)
    {
        //The server tells us what cipher types it accepts. For now we just ignore it
        //The list is normally just 01 02.
        eCipherType = *pMsg++;
        nParsed ++;
    }

    //Then two bytes for total size of the CA list, in bytes.
    nTotalSize  = *pMsg++;
    nTotalSize<<= 8;
    nTotalSize += *pMsg++;
    nParsed += 2;

    while (nParsed < nMsgSize)
    {
        uint    nCASize = 0;

        //First the size of the CA Identity
        nCASize  = *pMsg++; 
        nCASize <<= 8;
        nCASize += *pMsg++;
        nParsed += 2;

        //Parse each CA Identity. We are supposed to save this information X509NAME caName
        //for later use to find the correct client certificate to use. For now ignore it.
        nParse = ParseX509ID(&gTempCA, pMsg, nCASize);
        //assert(nParse == nCASize);

        pMsg += nParse;
        nParsed += nParse;
    }

    //assert(nParsed == nMsgSize); //Make sure we parsed the exact size.

    //We received server certificate so next to come is ServerHelloDone.
    //We also need to set a flag to indicate we need to get the client certificate.
    pSSL->eState = SSLSTATE_SERVER_CERTREQUEST; //Equivalent to SSLSTATE_SERVER_HELLO_DONE

    return nParsed;
}


/******************************************************************************
* Function:     ParseAppData
*
* Description:  Parse incoming network message that is CONTENT_APPLICATION_DATA.
*               since the data is not SSL handshake but application data to be
*               interpretted by application level code, we simply copy it over.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseAppData
(
    SSL*                    pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    if (pSSL->appoutMsg == NULL)
    {
        //No buffer. So we share the serverMsg buffer
        pSSL->appoutMsg = (uchar*)pMsg;
    }
    else
    {
    memmove(
        &(pSSL->appoutMsg[pSSL->nAppOutSize]),
        pMsg,
        nMsgSize
        );
    }

    pSSL->nAppOutSize += nMsgSize;

    return nMsgSize;
}


/******************************************************************************
* Function:     CreateFinishedMsg
*
* Description:  Create the Client Finished or Server Finished message. It can
*               be used by both the client and server, depending on the flag.
*
* Returns:      Number of bytes of constructed message.
******************************************************************************/
uint CreateFinishedMsg
(
    SSL*            pSSL,
    uint    bIsClient,  //ISCLIENT=TRUE for Client, ISSERVER=FALSE for Server
    uchar*  pMsgBuff,
    uint    nBuffSize
)
{
    int             i;
    uchar*  pMsg = pMsgBuff;
    MD5             md5Ctx;
    SHA             shaCtx;
    const CIPHER*   pMd5 = &(gpCipherSet->md5);
    const CIPHER*   pSha = &(gpCipherSet->sha1);

    md5Ctx = pSSL->md5Ctx;
    shaCtx = pSSL->sha1Ctx;

    if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
    {
    //For SSL 3.0
    pMd5->Input(&md5Ctx, bIsClient?SENDER_CLIENT:SENDER_SERVER, 4);
    pMd5->Input(&md5Ctx, pSSL->masterSecret, sizeof(pSSL->masterSecret));
    pMd5->Input(&md5Ctx, PAD1, PADSIZE_MD5);
    pMd5->Digest(&md5Ctx, pMsg);

    //Md5Init(&md5Ctx);
    pMd5->Init(&md5Ctx, pMd5->pIData);

    pMd5->Input(&md5Ctx, pSSL->masterSecret, sizeof(pSSL->masterSecret));
    pMd5->Input(&md5Ctx, PAD2, PADSIZE_MD5);
    pMd5->Input(&md5Ctx, pMsg, MD5_SIZE);
    pMd5->Digest(&md5Ctx, pMsg);
    //Done with MD5 hash calculation

    pMsg += MD5_SIZE;

    //Now we calculate the SHA1 Hash for the Finished Message.
    pSha->Input(&shaCtx, bIsClient?SENDER_CLIENT:SENDER_SERVER, 4);
    pSha->Input(&shaCtx, pSSL->masterSecret, sizeof(pSSL->masterSecret));
    pSha->Input(&shaCtx, PAD1, PADSIZE_SHA);
    pSha->Digest(&shaCtx, pMsg);

    pSha->Input(&shaCtx, pSSL->masterSecret, sizeof(pSSL->masterSecret));
    pSha->Input(&shaCtx, PAD2, PADSIZE_SHA);
    pSha->Input(&shaCtx, pMsg, SHA1_SIZE);
    pSha->Digest(&shaCtx, pMsg);
    //Done with SHA1 hash calculation

    pMsg += SHA1_SIZE;

    }
    else
    {
    //For SSL 3.1
#define pMD5HASH   (&(dataBlock[0]))
#define pSHAHASH   (&(dataBlock[MD5_SIZE]))
#define pMD5DIGEST (&(dataBlock[MD5_SIZE+SHA1_SIZE]))
#define pSHADIGEST (&(dataBlock[MD5_SIZE*2+SHA1_SIZE]))

    const char*     pClientLabel = CLIENT_LABEL;    //"client finished";
    const char*     pServerLabel = SERVER_LABEL;    //"server finished";
    uchar   dataBlock[MD5_SIZE*2+SHA1_SIZE*2];    //A worker data
    VDATA           vectBlocks[5] = {
        {(const uchar*)pClientLabel, 15},
        {NULL, 0},
        {(const uchar*)pClientLabel, 15},
        {pMD5DIGEST, MD5_SIZE+SHA1_SIZE},
        {NULL, 0}
        };
    HMAC            hMAC;

    vectBlocks[0].pData = &(pSSL->masterSecret[0]);
    vectBlocks[0].nSize = ((MASTER_SECRET_LEN+1)>>1);
    HMAC_InitMD5(&hMAC, dataBlock, &(vectBlocks[0]));

    vectBlocks[0].pData = &(pSSL->masterSecret[MASTER_SECRET_LEN>>1]);
    vectBlocks[0].nSize = ((MASTER_SECRET_LEN+1)>>1);
    HMAC_InitSHA1(&hMAC, dataBlock, &(vectBlocks[0]));

    vectBlocks[0].pData = (const uchar*)((bIsClient)?pClientLabel:pServerLabel);
    vectBlocks[0].nSize = 15; //strlen(vectBlocks[0].pData);

    vectBlocks[2] = vectBlocks[0];

    pMd5->Digest(&md5Ctx, pMD5DIGEST);
    pSha->Digest(&shaCtx, pSHADIGEST);

    //Calculate A(1) for HMAC_MD5 and HMAC_SHA1
    HMAC_MD5 (&hMAC, pMD5HASH, &(vectBlocks[2]));
    HMAC_SHA1(&hMAC, pSHAHASH, &(vectBlocks[2]));

    //Calculate HMAC_MD5(1) and HMAC_SHA1(1)
    vectBlocks[1].pData = pMD5HASH;
    vectBlocks[1].nSize = MD5_SIZE;
    HMAC_MD5 (&hMAC, pMD5HASH, &(vectBlocks[1]));
    vectBlocks[1].pData = pSHAHASH;
    vectBlocks[1].nSize = SHA1_SIZE;
    HMAC_SHA1(&hMAC, pSHAHASH, &(vectBlocks[1]));


    for (i=0; i<TLS_VERIFY_LEN; i++)
    {
        *pMsg++ = pMD5HASH[i] ^ pSHAHASH[i];
    }

#undef  pSHADIGEST //(&(dataBlock[MD5_SIZE*2+SHA1_SIZE]))
#undef  pMD5DIGEST //(&(dataBlock[MD5_SIZE+SHA1_SIZE]))
#undef  pSHAHASH   //(&(dataBlock[MD5_SIZE]))
#undef  pMD5HASH   //(&(dataBlock[0]))
    }

    memcpy((bIsClient)?pSSL->clientVerify:pSSL->serverVerify, pMsgBuff, (pMsg-pMsgBuff));

    return (pMsg - pMsgBuff);
}


/******************************************************************************
* Function:     CalculateMAC
*
* Description:  Calculate the MAC signature based on the state of the SSL engine.
*
* Returns:      Size of MAC signature in bytes.
******************************************************************************/
uint CalculateMAC
(
    SSL*            pSSL,
    uint    bIsClient,  //TRUE for Client, FALSE for Server
    uchar*  pMac,
    uchar   cMsgType,
    const uchar*    pMsg,
    uint    nMsgSize
)
{
    SSL_CIPHER      eCipher;
    uint    nMacSize = MD5_SIZE;
    uchar*  pMacSecret;
    uint    nSequenceL, nSequenceH;
    uchar*  pTemp;
    uchar   temp[16];

    //Get the sequence number, and BTW increment it in pSSL.
    if (bIsClient)
    {
        eCipher    = pSSL->eClientCipher;
        pMacSecret = pSSL->clientMacSecret;
        nSequenceL = pSSL->clientSequenceL;
        nSequenceH = pSSL->clientSequenceH;
        if ((++(pSSL->clientSequenceL)) == 0)
        {
            pSSL->clientSequenceH ++;
        }
    }
    else
    {
        eCipher    = pSSL->eServerCipher;
        pMacSecret = pSSL->serverMacSecret;
        nSequenceL = pSSL->serverSequenceL;
        nSequenceH = pSSL->serverSequenceH;
        if ((++(pSSL->serverSequenceL)) == 0)
        {
            pSSL->serverSequenceH ++;
        }
    }

    pTemp = temp;

    *pTemp++ = (uchar)(nSequenceH>>24);
    *pTemp++ = (uchar)(nSequenceH>>16);
    *pTemp++ = (uchar)(nSequenceH>>8);
    *pTemp++ = (uchar)(nSequenceH>>0);

    *pTemp++ = (uchar)(nSequenceL>>24);
    *pTemp++ = (uchar)(nSequenceL>>16);
    *pTemp++ = (uchar)(nSequenceL>>8);
    *pTemp++ = (uchar)(nSequenceL>>0);

    *pTemp++ = cMsgType;

    if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
    {
    //SSL 3.0 has no version info here.
    }
    else
    {
    //SSL 3.1 has the version bytes here
    *pTemp++ = pSSL->preMasterSecret[0]; //SSL_VERSION_MAJOR;
    *pTemp++ = pSSL->preMasterSecret[1]; //SSL_VERSION_MINOR1;
    }

    *pTemp++ = (uchar)(nMsgSize>>8);
    *pTemp++ = (uchar)(nMsgSize>>0);

    if ((pSSL->preMasterSecret[1] < SSL_VERSION_MINOR1) ||
        (SSL_VERSION_MINOR < SSL_VERSION_MINOR1) )
    //For SSL 3.0
    switch (eCipher)
    {
    case CIPHER_RSA_RC4_40_MD5:
    case CIPHER_RSA_RC4_128_MD5:
        {
            MD5     md5Ctx;
            const CIPHER* pMd5 = &(gpCipherSet->md5);

            nMacSize = MD5_SIZE;

            //Md5Init(&md5Ctx);
            pMd5->Init(&md5Ctx, pMd5->pIData);
            pMd5->Input(&md5Ctx, pMacSecret, MAC_SECRET_LEN);
            pMd5->Input(&md5Ctx, PAD1, PADSIZE_MD5);

            pMd5->Input(&md5Ctx, temp, (uint)(pTemp-temp));
            pMd5->Input(&md5Ctx, pMsg, nMsgSize);

            pMd5->Digest(&md5Ctx, pMac);

            //Md5Init(&md5Ctx);
            pMd5->Init(&md5Ctx, pMd5->pIData);
            pMd5->Input(&md5Ctx, pMacSecret, MAC_SECRET_LEN);
            pMd5->Input(&md5Ctx, PAD2, PADSIZE_MD5);
            pMd5->Input(&md5Ctx, pMac, nMacSize);
            pMd5->Digest(&md5Ctx, pMac);
        }
        break;
    case CIPHER_RSA_RC4_128_SHA:
        {
            SHA     shaCtx;
            const CIPHER*   pSha = &(gpCipherSet->sha1);

            nMacSize = SHA1_SIZE;

            pSha->Init(&shaCtx, pSha->pIData);
            pSha->Input(&shaCtx, pMacSecret, SHA1_SIZE);
            pSha->Input(&shaCtx, PAD1, PADSIZE_SHA);

            pSha->Input(&shaCtx, temp, (uint)(pTemp-temp));
            pSha->Input(&shaCtx, pMsg, nMsgSize);

            pSha->Digest(&shaCtx, pMac);

            pSha->Init(&shaCtx, pSha->pIData);
            pSha->Input(&shaCtx, pMacSecret, SHA1_SIZE);
            pSha->Input(&shaCtx, PAD2, PADSIZE_SHA);
            pSha->Input(&shaCtx, pMac, nMacSize);
            pSha->Digest(&shaCtx, pMac);
        }
        break;
    default:
        //Unsupported cipher. Let's assume MAC size same as MD5.
        assert(0);
        nMacSize = 0;
        break;
    }
    else
    {
    //For SSL 3.1
    uchar   hashBlock[BLOCK_LEN];
    VDATA   vectBlocks[4] = {
        {pMacSecret, MAC_SECRET_LEN},
        {temp, (uint)(pTemp-temp)},
        {pMsg, nMsgSize},
        {NULL, 0}
        };
    HMAC    hMac;

    switch (eCipher)
    {
    case CIPHER_RSA_RC4_40_MD5:
    case CIPHER_RSA_RC4_128_MD5:
        {
            nMacSize = MD5_SIZE;

            HMAC_InitMD5(&hMac, hashBlock, &(vectBlocks[0]));
            HMAC_MD5(&hMac, pMac, &(vectBlocks[1]));
        }
        break;
    case CIPHER_RSA_RC4_128_SHA:
        {
            nMacSize = SHA1_SIZE;
            vectBlocks[0].nSize = SHA1_SIZE;

            HMAC_InitSHA1(&hMac, hashBlock, &(vectBlocks[0]));
            HMAC_SHA1(&hMac, pMac, &(vectBlocks[1]));
        }
        break;
    default:
        //Unsupported cipher. Let's assume MAC size same as MD5.
        nMacSize = 0;
        break;
    }
    }

    return nMacSize;
}


/******************************************************************************
* Function:     EncryptWithMAC
*
* Description:  Calculate the MAC, attach to message and then encrypt.
*
* Returns:      Bytes of the MAC block attached before encryption.
******************************************************************************/
uint EncryptWithMAC
(
    SSL*    pSSL,
    uint    bIsClient,
    uchar   cContentType,
    uchar*  pMsg,
    uint    nMsgSize
)
{
    uint    nMacSize = MD5_SIZE;

    nMacSize = CalculateMAC(
        pSSL,
        bIsClient,
        &(pMsg[nMsgSize]),
        cContentType,
        pMsg,
        nMsgSize
        );

    //Now we do the encryption, after the MAC is appended.
    RC4Code(
        (bIsClient)?(&(pSSL->clientCipher)):(&(pSSL->serverCipher)),
        pMsg,
        nMsgSize+nMacSize
        );

    return nMacSize;
}


/******************************************************************************
* Function:     CreateNetMsg
*
* Description:  Package and encrypt an out-going network data package.
*
* Returns:      Total size of the package when properly encrypted and packaged.
*               ZERO if not enough space to put the package in.
******************************************************************************/
uint CreateNetMsg
(
    SSL*        pSSL,
    uchar       cContentType,
    const uchar* pData,
    uint        nDataSize
)
{
    uint       nLen, nMacSize=MD5_SIZE, nEncryptSize;
    uchar*      pMsgBuff = &(pSSL->netoutMsg[pSSL->nNetOutSize]);
    uchar*      pMsg = pMsgBuff;
    uchar*      pEncryptData;

    //Do we have enough space to contain the package?
    nLen = 5 + nMacSize + nDataSize;
    if ((nLen + pSSL->nNetOutSize) > sizeof(pSSL->netoutMsg))
    {
        return 0; //Not enough space. No package is added, so return 0.
    }

    *pMsg++ = cContentType;

    *pMsg++ = pSSL->preMasterSecret[0]; //SSL_VERSION_MAJOR;
    *pMsg++ = (SSL_VERSION_MINOR<pSSL->preMasterSecret[1])?SSL_VERSION_MINOR:pSSL->preMasterSecret[1];

    nEncryptSize = nDataSize + nMacSize;

    //This content size may not be correct. Will come back to fill in again.
    *pMsg++ = (uchar)(nEncryptSize>>8);
    *pMsg++ = (uchar)(nEncryptSize>>0);

    //Starting here is data that needs to be encrypted.
    pEncryptData = pMsg;

    memcpy(pMsg, pData, nDataSize);
    pMsg += nDataSize;

    //Now calculate the MAC of the message and encrypt.
    pMsg += nMacSize = EncryptWithMAC(
        pSSL, 
        TRUE,       //For Client
        (*pMsgBuff),
        pEncryptData,
        nDataSize
        );

    nEncryptSize = nDataSize + nMacSize;   //Now we added the size of MAC

    pEncryptData[-2] = (uchar)(nEncryptSize>>8);
    pEncryptData[-1] = (uchar)(nEncryptSize>>0);

    nLen = pMsg - pMsgBuff;

    pSSL->nNetOutSize += nLen;

    return nLen;
}


/******************************************************************************
* Function:     ParseAlertMsg
*
* Description:  Parse incoming message that belongs to CONTENT_ALERT.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseAlertMsg
(
    SSL*        pSSL,
    const uchar* pMsg,
    uint        nMsgSize
)
{
    uchar   cCategory, cType;

    cCategory = *pMsg++;
    cType     = *pMsg++;

    switch (cType)
    {
    case ALERT_NOTIFY_CLOSE:
        CreateAlertMsg(pSSL, ALERT_WARNING, ALERT_NOTIFY_CLOSE);
        pSSL->eState = SSLSTATE_DISCONNECTING;
        break;
    default:
        pSSL->eState = SSLSTATE_DISCONNECTING;
        break;
    }

    return nMsgSize;
}


/******************************************************************************
* Function:     CreateAlertMsg
*
* Description:  Create a CONTENT_ALERT message.
*
* Returns:      Bytes of constructed message.
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

    return CreateNetMsg(pSSL, CONTENT_ALERT, msg, sizeof(msg));
}
