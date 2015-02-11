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
*  File Name:       sslTest.c
*
*  Description:     Running SSL/TLS dry run Test.
*
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         6/28/2014 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <windows.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>

#include "sslTest.h"

#include "cert.h"
#include "ssl.h"
#include "sslServer.h"

#include "cipher.h"


#define SERVER_MAX  32768


//#define DO_CLIENT_AUTHENTICATION    1
#define DO_CLIENT_AUTHENTICATION    0


uint    myRand();


const CERTKEY_INFO* InitClientCertKeyInfo();

void DumpBinary(const uchar* pOutputData, uint nSize, const char* pText);


static int ClientPreProcess(SSL_PARAMS* pClient, SSL_PARAMS* pServer);
static int ClientPostProcess(SSL_PARAMS* pClient, SSL_PARAMS* pServer);
static int ServerPreProcess(SSL_PARAMS* pClient, SSL_PARAMS* pServer);
static int ServerPostProcess(SSL_PARAMS* pClient, SSL_PARAMS* pServer);


uint myRand()
{
    static uint nNum = 0;

    nNum = (nNum>>15)|(nNum<<17);
    nNum ^= rand();
    nNum = (nNum>>11)|(nNum<<21);
    nNum ^= rand();

    return nNum;
}


const CERTKEY_INFO* InitClientCertKeyInfo()
{
    //To be implemented.
    return NULL;
}


void DumpBinary(const uchar* pOutputData, uint nSize, const char* pText)
{
    uint    i;
    static uint nC = 0;

    printf("[%d]%s[%d]\r\n", nC++, pText, nSize);

    if (nSize > 256)
    {
        nSize = 256;
        printf("Limiting to only %d bytes dump out\r\n", nSize);
    }

    for (i=0; i<nSize; i++)
    {
        if (i&7)
        {
            printf(", %02X", pOutputData[i]);
        }
        else if (i)
        {
            printf(",\r\n    %02X", pOutputData[i]);
        }
        else
        {
            printf("    %02X", pOutputData[i]);
        }
    }

    printf("\r\n");
}



char    gClientToServerMsg[8192];
char    gServerToClientMsg[8192];

uchar   bClientToServer[8192];
uchar   bServerToClient[8192];


#include "certSamples.h"


//The content here can be over-ridden by appliation level code.
CERTKEY_INFO gServerCertKey = {
    NULL,
    NULL,
    2048,
    gMySSLCert,
    gMySSLPublicKey,    //gMyPubKey,
    gMySSLPrivateKey     //gMyPriKey,
};


uint    DoSSLTest()
{
    uint    ret=0, ret1, iT = 0;
    uint    nClientToServer=0, nServerToClient=0;
    HSSL    hClient = NULL;
    HSSL    hServer = NULL;
    SSL_STATE   eClient, eServer;
    const CIPHERSET* pCipherSet = NULL;
    SSL_PARAMS  cParams;
    SSL_PARAMS  sParams;

    
    if (0)
    {
        int     i,j,len=0;
        uchar   oneBlock[8];
        FILE*   fin = fopen("C:\\App\\MCrypt\\data\\www.internet.org_3.cer", "rb");

        while (!feof(fin))
        {
            j = fread(oneBlock, 1, 8, fin);
            if (j<=0) break;
            printf("\r\n");
            for (i=0; i<j; i++)
            {
                printf(" 0x%02X,", oneBlock[i]);
            }
            len += j;
        }
        printf("\r\n\r\n%d\r\n", len);

        fclose(fin);
    }

    memset(&cParams, 0, sizeof(cParams));
    memset(&sParams, 0, sizeof(sParams));

    srand(1234);

    pCipherSet = InitCiphers(&gCipherSet, NULL);

    ret |= SSL_Initialize(malloc, free, myRand, pCipherSet, 8192, 8192);

    //ret |= SSL_AddRootCertificate(gGeoTrustRoot, sizeof(gGeoTrustRoot), 0);
    //ret |= SSL_AddRootCertificate(gRootCert, sizeof(gRootCert), 0);

    ret |= SSL_AddRootCertificate(gMySSLRootCert, sizeof(gMySSLRootCert), 0);

    ret |= SSL_Create(&hClient, NULL);
    ret |= SSL_Create(&hServer, &gServerCertKey);

    //Pretend that client and server are TCP connected.
    cParams.eState = SSLSTATE_TCPCONNECTED;
    sParams.eState = SSLSTATE_TCPCONNECTED;

    eClient = eServer = SSLSTATE_TCPCONNECTED;

    for (iT = 0; iT < 10; iT++)
    {
        printf("********** Iteration %d **************\r\n", iT);

        //First the client side
        ClientPreProcess(&cParams, &sParams);

        ret |= ret1 = SSL_Process(&cParams, hClient);
        if (ret1)
        {
            printf("SSL_Process ERROR %d\r\n", ret1);
            break;
        }

        if (eClient != cParams.eState)
        {
            printf("==== CLNT Changed State to %d ====\r\n", eClient = cParams.eState);
        }

        ClientPostProcess(&cParams, &sParams);

        // Now client to server activity.
        nClientToServer = 0;
        memset(&bClientToServer, 0, sizeof(bClientToServer));

        if ((cParams.nNetOutSize != 0) && (NULL != cParams.pNetOutData))
        {
            nClientToServer = cParams.nNetOutSize;
            memcpy(bClientToServer, cParams.pNetOutData, nClientToServer);
            sParams.nNetInSize = nClientToServer;
            sParams.pNetInData = bClientToServer;
        }
        else
        {
            sParams.nNetInSize = 0;
            sParams.pNetInData = NULL;
        }

        //Now the server side
        ServerPreProcess(&cParams, &sParams);

        if (iT == 100)
        {
            iT = iT;
            if (sParams.eState == SSLSTATE_CONNECTED)
            {
                sParams.eState = SSLSTATE_HELLO_REQUEST;

                //sParams.nAppInSize = 0;
                //sParams.pAppInData = NULL;
            }
        }

        ret1 = SSL_Server(&sParams, hServer);
        ret |= ret1;
        if (ret1)
        {
            printf("SSL_Server ERROR %d\r\n", ret1);
            break;
        }

        if (eServer != sParams.eState)
        {
            printf("==== SRVR Changed State to %d ====\r\n", eServer = sParams.eState);
        }

        ServerPostProcess(&cParams, &sParams);

        // Now server to client activity.
        nServerToClient = 0;
        memset(&bServerToClient, 0, sizeof(bServerToClient));


        if ((sParams.nNetOutSize != 0) && (NULL != sParams.pNetOutData))
        {
            nServerToClient = sParams.nNetOutSize;
            memcpy(bServerToClient, sParams.pNetOutData, nServerToClient);
            cParams.nNetInSize = nServerToClient;
            cParams.pNetInData = bServerToClient;
        }
        else
        {
            cParams.nNetInSize = 0;
            cParams.pNetInData = NULL;
        }
    }

    SSL_Destroy(hServer);
    SSL_Destroy(hClient);

    ret |= SSL_Cleanup();

    return ret;
}


int ClientPreProcess(SSL_PARAMS* pClient, SSL_PARAMS* pServer)
{
    int         ret = 0, ret1 = 0;
    SSL_STATE   eStatus = SSLSTATE_RESET;
    SSL_PARAMS*    pParams = pClient;
    SSL_PARAMS*    pParams2 = pServer;

    eStatus = pParams->eState;

    //First set cParams before the big call.
    switch (eStatus)
    {
    case SSLSTATE_UNCONNECTED:
        break;

    case SSLSTATE_TCPCONNECTED: //       = 3,    //Application tells us TCP connected. This triggers handshake.
        break;

    case SSLSTATE_HANDSHAKE_BEGIN: //    = 4,    //Initialize HandShake & goto SSLSTATE_CLIENT_HELLO
        break;

    case SSLSTATE_CLIENT_HELLO: //       = 5,    //Send out ClientHello & goto SSLSTATE_SERVER_HELLO
        break;

    case SSLSTATE_SERVER_HELLO: //       = 6,    //Wait ServerHello, if reuse SessionID, goto SSLSTATE_SERVER_FINISH1, else goto SSLSTATE_SERVER_HELLO_DONE
        break;

    case SSLSTATE_SERVER_CERTIFICATE: // = 7,    //Wait Server Certificate, then go to SSLSTATE_SERVER_HELLO_DONE
        break;

    case SSLSTATE_CERTIFICATE_REQUEST:
        break;

    case SSLSTATE_CERTIFICATE_REQUESTING:       //We are asked for a client certificate. So we need to supply it here
        //Supply the client certificate.
        pParams->nInXData.ptr = (void*)InitClientCertKeyInfo();
        //And then move to the next status:
        pParams->eState = SSLSTATE_CERTIFICATE_SUPPLIED;
        break;

    case SSLSTATE_SERVER_HELLO_DONE: //  = 8,    //Wait ServerHelloDone & goto SSLSTATE_CERTIFICATE_VERIFY.
        break;

    case SSLSTATE_CERTIFICATE_VERIFY: // = 9,    //Verify server certificate and goto SSLSTATE_CERTIFICATE_VERIFIED
        break;

    case SSLSTATE_CERTIFICATE_VERIFIED: //=10,   //Certificate verified. Go to SSLSTATE_CLIENT_KEYEXCHANGE.
        break;

    case SSLSTATE_CERTIFICATE_ACCEPTING: //=11,  //Wait for application to accept questionable certificate.
        break;

    case SSLSTATE_CERTIFICATE_REJECTED: //=12,   //Bad certificate rejected. Goto SSLSTATE_ABORTING.
        break;

    case SSLSTATE_CERTIFICATE_EXPIRED: //= 13,   //Certificate expired. Goto SSLSTATE_ABORTING.
        break;

    case SSLSTATE_CERTIFICATE_ACCEPTED: //=15,   //Certificate accepted by App, goto SSLSTATE_CLIENT_KEYEXCHANGE.
        break;

    case SSLSTATE_CLIENT_KEYEXCHANGE: // = 16,   //Send ClientKeyExchange & goto SSLSTATE_CLIENT_FINISH1.
        break;

    case SSLSTATE_SERVER_FINISH1: //     = 17,   //Wait for ServerFinish & goto SSLSTATE_CLIENT_FINISH2.
        break;

    case SSLSTATE_CLIENT_FINISH1: //     = 18,   //Send ChangeCipher, Finish & goto SSLSTATE_SERVER_FINISH2
        break;

    case SSLSTATE_CLIENT_FINISH2: //     = 19,   //Send ChangeCipher, Finish & goto SSLSTATE_HANDSHAKE_DONE
        break;

    case SSLSTATE_SERVER_FINISH2: //     = 20,   //Wait for ServerFinish & goto SSLSTATE_HANDSHAKE_DONE.
        break;

    case SSLSTATE_HANDSHAKE_DONE: //     = 21,   //Verify every thing OK & goto SSLSTATE_CONNECTED, else
        break;

    case SSLSTATE_CONNECTED: //          = 32,   //We can now exchange application data encrypted.
        break;

    case SSLSTATE_DISCONNECT: //         = 48,   //App tells us to initiate a disconnect sequence.
        break;

    case SSLSTATE_DISCONNECTING: //      = 49,   //We were told by the server to disconnect. Tell App to disconnect
        pParams->eState = SSLSTATE_DISCONNECTED;
        break;

    case SSLSTATE_DISCONNECTED: //       = 50,   //App tells us TCP disconnected. Cleanup and goto SSLSTATE_UNCONNECTED
        break;

    case SSLSTATE_ABORTING: //           = 51,   //Notify server we are aborting a failed connection, then goto SSLSTATE_ABORTED
        break;

    case SSLSTATE_ABORTED: //            = 52,   //Failed connection aborted. App disconnect TCP and goto SSLSTATE_DISCONNECTED
        break;

    default:
        printf("**** L%d Wrong State %d\r\n*************", __LINE__, eStatus);
        break;
    }

    pParams->pAppInData = 0;
    pParams->nAppInSize = 0;

    if (eStatus == SSLSTATE_CONNECTED)
    {
        static int  iIterator = 0;

        //Send server some message;
        sprintf(gClientToServerMsg, "CLNT MSG%d: Hello!\r\n", iIterator++);

        printf("Client send to server app message:\r\n%s\r\n", gClientToServerMsg);
        pParams->pAppInData = (const uchar*)gClientToServerMsg;
        pParams->nAppInSize = strlen(gClientToServerMsg);
    }

    return ret;
}


int ClientPostProcess(SSL_PARAMS* pClient, SSL_PARAMS* pServer)
{
    int         ret = 0, ret1 = 0;
    SSL_STATE   eStatus = SSLSTATE_RESET;
    SSL_PARAMS*    pParams = pClient;
    SSL_PARAMS*    pParams2 = pServer;

    eStatus = pParams->eState;

    //First set cParams before the big call.
    switch (eStatus)
    {
    case SSLSTATE_UNCONNECTED:
        break;

    case SSLSTATE_TCPCONNECTED: //       = 3,    //Application tells us TCP connected. This triggers handshake.
        break;

    case SSLSTATE_HANDSHAKE_BEGIN: //    = 4,    //Initialize HandShake & goto SSLSTATE_CLIENT_HELLO
        break;

    case SSLSTATE_CLIENT_HELLO: //       = 5,    //Send out ClientHello & goto SSLSTATE_SERVER_HELLO
        break;

    case SSLSTATE_SERVER_HELLO: //       = 6,    //Wait ServerHello, if reuse SessionID, goto SSLSTATE_SERVER_FINISH1, else goto SSLSTATE_SERVER_HELLO_DONE
        if (pParams->nNetOutSize == 0) break;
#ifdef SSL_TEST_TRACE
        ret1 |= pParams->nNetOutSize - sizeof(gTrace1);
        ret1 |= memcmp(gTrace1, pParams->pNetOutData, sizeof(gTrace1));
        ret |= ret1;
        ASSERT(ret == 0);
#endif //SSL_TEST_TRACE
        break;

    case SSLSTATE_SERVER_CERTIFICATE: // = 7,    //Wait Server Certificate, then go to SSLSTATE_SERVER_HELLO_DONE
        break;

    case SSLSTATE_CERTIFICATE_REQUESTING:       //We are asked for a client certificate. So we need to supply it here
        break;

    case SSLSTATE_SERVER_HELLO_DONE: //  = 8,    //Wait ServerHelloDone & goto SSLSTATE_CERTIFICATE_VERIFY.
        break;

    case SSLSTATE_CERTIFICATE_VERIFY: // = 9,    //Verify server certificate and goto SSLSTATE_CERTIFICATE_VERIFIED
        break;

    case SSLSTATE_CERTIFICATE_VERIFIED: //=10,   //Certificate verified. Go to SSLSTATE_CLIENT_KEYEXCHANGE.
        break;

    case SSLSTATE_CERTIFICATE_ACCEPTING: //=11,  //Wait for application to accept questionable certificate.
        pParams->eState = SSLSTATE_CERTIFICATE_ACCEPTED;
        break;

    case SSLSTATE_CERTIFICATE_REJECTED: //=12,   //Bad certificate rejected. Goto SSLSTATE_ABORTING.
        break;

    case SSLSTATE_CERTIFICATE_EXPIRED: //= 13,   //Certificate expired. Goto SSLSTATE_ABORTING.
        break;

    case SSLSTATE_CERTIFICATE_ACCEPTED: //=15,   //Certificate accepted by App, goto SSLSTATE_CLIENT_KEYEXCHANGE.
        break;

    case SSLSTATE_CLIENT_KEYEXCHANGE: // = 16,   //Send ClientKeyExchange & goto SSLSTATE_CLIENT_FINISH1.
        break;

    case SSLSTATE_SERVER_FINISH1: //     = 17,   //Wait for ServerFinish & goto SSLSTATE_CLIENT_FINISH2.
        break;

    case SSLSTATE_CLIENT_FINISH1: //     = 18,   //Send ChangeCipher, Finish & goto SSLSTATE_SERVER_FINISH2
        break;

    case SSLSTATE_CLIENT_FINISH2: //     = 19,   //Send ChangeCipher, Finish & goto SSLSTATE_HANDSHAKE_DONE
        break;

    case SSLSTATE_SERVER_FINISH2: //     = 20,   //Wait for ServerFinish & goto SSLSTATE_HANDSHAKE_DONE.
        if (pParams->nNetOutSize == 0) break;
#ifdef SSL_TEST_TRACE
        ret1 |= pParams->nNetOutSize - sizeof(gTrace3);
        ret1 |= memcmp(gTrace3, pParams->pNetOutData, sizeof(gTrace3));
        ret |= ret1;
        ASSERT(ret == 0);
#endif //SSL_TEST_TRACE
        break;

    case SSLSTATE_HANDSHAKE_DONE: //     = 21,   //Verify every thing OK & goto SSLSTATE_CONNECTED, else
        break;

    case SSLSTATE_CONNECTED: //          = 32,   //We can now exchange application data encrypted.
        break;

    case SSLSTATE_DISCONNECT: //         = 48,   //App tells us to initiate a disconnect sequence.
        break;

    case SSLSTATE_DISCONNECTING: //      = 49,   //We were told by the server to disconnect. Tell App to disconnect
        break;

    case SSLSTATE_DISCONNECTED: //       = 50,   //App tells us TCP disconnected. Cleanup and goto SSLSTATE_UNCONNECTED
        break;

    case SSLSTATE_ABORTING: //           = 51,   //Notify server we are aborting a failed connection, then goto SSLSTATE_ABORTED
        break;

    case SSLSTATE_ABORTED: //            = 52,   //Failed connection aborted. App disconnect TCP and goto SSLSTATE_DISCONNECTED
        break;

    default:
        printf("**** L%d Wrong State %d\r\n*************", __LINE__, eStatus);
        break;
    }

    if (pParams->nNetOutSize > 0)
    {
        DumpBinary(
            pParams->pNetOutData,
            pParams->nNetOutSize,
            "Client Send to Server"
            );
    }

    if (pParams->nAppOutSize > 0)
    {
        memcpy(gServerToClientMsg, pParams->pAppOutData, pParams->nAppOutSize);
        gServerToClientMsg[pParams->nAppOutSize] = 0x00;
        printf("Client Receives Server App Msg[%d]:\r\n%s\r\n", pParams->nAppOutSize, gServerToClientMsg);
    }

    pParams2->eState = pParams->eState;

    return ret;
}


int ServerPreProcess(SSL_PARAMS* pClient, SSL_PARAMS* pServer)
{
    int         ret = 0, ret1 = 0;
    SSL_STATE   eStatus = SSLSTATE_RESET;
    SSL_PARAMS*    pParams = pServer;
    SSL_PARAMS*    pParams2 = pClient;

    eStatus = pParams->eState;

    //First set cParams before the big call.
    switch (eStatus)
    {
    case SSLSTATE_UNCONNECTED:
        break;

    case SSLSTATE_TCPCONNECTED: //       = 3,    //Application tells us TCP connected. This triggers handshake.
        break;

    case SSLSTATE_HANDSHAKE_BEGIN: //    = 4,    //Initialize HandShake & goto SSLSTATE_CLIENT_HELLO
        break;

    case SSLSTATE_CLIENT_HELLO: //       = 5,    //Send out ClientHello & goto SSLSTATE_SERVER_HELLO
        break;

    case SSLSTATE_SERVER_HELLO: //       = 6,    //Wait ServerHello, if reuse SessionID, goto SSLSTATE_SERVER_FINISH1, else goto SSLSTATE_SERVER_HELLO_DONE
        break;

    case SSLSTATE_SERVER_CERTIFICATE: // = 7,    //Wait Server Certificate, then go to SSLSTATE_SERVER_HELLO_DONE
        break;

    case SSLSTATE_CERTIFICATE_REQUESTING:       //We are asked for a client certificate. So we need to supply it here
        break;

    case SSLSTATE_SERVER_HELLO_DONE: //  = 8,    //Wait ServerHelloDone & goto SSLSTATE_CERTIFICATE_VERIFY.
        break;

    case SSLSTATE_CERTIFICATE_VERIFY: // = 9,    //Verify server certificate and goto SSLSTATE_CERTIFICATE_VERIFIED
        break;

    case SSLSTATE_CERTIFICATE_VERIFIED: //=10,   //Certificate verified. Go to SSLSTATE_CLIENT_KEYEXCHANGE.
        break;

    case SSLSTATE_CERTIFICATE_ACCEPTING: //=11,  //Wait for application to accept questionable certificate.
        break;

    case SSLSTATE_CERTIFICATE_REJECTED: //=12,   //Bad certificate rejected. Goto SSLSTATE_ABORTING.
        break;

    case SSLSTATE_CERTIFICATE_EXPIRED: //= 13,   //Certificate expired. Goto SSLSTATE_ABORTING.
        break;

    case SSLSTATE_CERTIFICATE_ACCEPTED: //=15,   //Certificate accepted by App, goto SSLSTATE_CLIENT_KEYEXCHANGE.
        break;

    case SSLSTATE_CLIENT_KEYEXCHANGE: // = 16,   //Send ClientKeyExchange & goto SSLSTATE_CLIENT_FINISH1.
        break;

    case SSLSTATE_SERVER_FINISH1: //     = 17,   //Wait for ServerFinish & goto SSLSTATE_CLIENT_FINISH2.
        break;

    case SSLSTATE_CLIENT_FINISH1: //     = 18,   //Send ChangeCipher, Finish & goto SSLSTATE_SERVER_FINISH2
        break;

    case SSLSTATE_CLIENT_FINISH2: //     = 19,   //Send ChangeCipher, Finish & goto SSLSTATE_HANDSHAKE_DONE
        break;

    case SSLSTATE_SERVER_FINISH2: //     = 20,   //Wait for ServerFinish & goto SSLSTATE_HANDSHAKE_DONE.
        break;

    case SSLSTATE_HANDSHAKE_DONE: //     = 21,   //Verify every thing OK & goto SSLSTATE_CONNECTED, else
        break;

    case SSLSTATE_CONNECTED: //          = 32,   //We can now exchange application data encrypted.
        break;

    case SSLSTATE_DISCONNECT: //         = 48,   //App tells us to initiate a disconnect sequence.
        break;

    case SSLSTATE_DISCONNECTING: //      = 49,   //We were told by the server to disconnect. Tell App to disconnect
        pParams->eState = SSLSTATE_DISCONNECTED;
        break;

    case SSLSTATE_DISCONNECTED: //       = 50,   //App tells us TCP disconnected. Cleanup and goto SSLSTATE_UNCONNECTED
        break;

    case SSLSTATE_ABORTING: //           = 51,   //Notify server we are aborting a failed connection, then goto SSLSTATE_ABORTED
        break;

    case SSLSTATE_ABORTED: //            = 52,   //Failed connection aborted. App disconnect TCP and goto SSLSTATE_DISCONNECTED
        break;

    default:
        printf("**** L%d Wrong State %d\r\n*************", __LINE__, eStatus);
        break;
    }

    pParams->pAppInData = 0;
    pParams->nAppInSize = 0;

    if (pParams->nAppOutSize > 0)
    {
        static int iIterator = 0;

        memcpy(gClientToServerMsg, pParams->pAppOutData, pParams->nAppOutSize);
        gServerToClientMsg[pParams->nAppOutSize] = 0x00;
        printf("Server Receives Client App Msg:\r\n%s\r\n", gClientToServerMsg);

        sprintf(gServerToClientMsg, "SERVER MSG%d: Welcome!\r\n", iIterator++);
        pParams->pAppInData = (const uchar*)gServerToClientMsg;
        pParams->nAppInSize = strlen(gServerToClientMsg);

        if ((iIterator%37) == 36 && 0)
        {
            //Test big server message size
            pParams->nAppInSize = SERVER_MAX;
        }
    }

    return ret;
}


int ServerPostProcess(SSL_PARAMS* pClient, SSL_PARAMS* pServer)
{
    int         ret = 0, ret1 = 0;
    SSL_STATE   eStatus = SSLSTATE_RESET;
    SSL_PARAMS* pParams = pServer;
    SSL_PARAMS* pParams2 = pClient;

    eStatus = pParams->eState;

    //First set cParams before the big call.
    switch (eStatus)
    {
    case SSLSTATE_UNCONNECTED:
        break;

    case SSLSTATE_TCPCONNECTED: //       = 3,    //Application tells us TCP connected. This triggers handshake.
        break;

    case SSLSTATE_HANDSHAKE_BEGIN: //    = 4,    //Initialize HandShake & goto SSLSTATE_CLIENT_HELLO
        break;

    case SSLSTATE_CLIENT_HELLO: //       = 5,    //Send out ClientHello & goto SSLSTATE_SERVER_HELLO
        break;

    case SSLSTATE_CLIENT_CERTREQUEST:           //Server decides whether to request client certificate.
        if (DO_CLIENT_AUTHENTICATION)
        {
            pParams->nInXData.data = 1;
        }
        else
        {
            pParams->nInXData.data = 0;
        }
        break;

    case SSLSTATE_SERVER_HELLO: //       = 6,    //Wait ServerHello, if reuse SessionID, goto SSLSTATE_SERVER_FINISH1, else goto SSLSTATE_SERVER_HELLO_DONE
        if (DO_CLIENT_AUTHENTICATION)
        {
            pParams->nInXData.data = 1;
        }
        else
        {
            pParams->nInXData.data = 0;
        }
        break;
    case SSLSTATE_CERTIFICATE_REQUEST:
        break;

    case SSLSTATE_CERTIFICATE_REQUESTING:       //We are asked for a client certificate. So we need to supply it here
        break;


    case SSLSTATE_SERVER_CERTIFICATE: // = 7,    //Wait Server Certificate, then go to SSLSTATE_SERVER_HELLO_DONE
        break;

    case SSLSTATE_SERVER_HELLO_DONE: //  = 8,    //Wait ServerHelloDone & goto SSLSTATE_CERTIFICATE_VERIFY.
        break;

    case SSLSTATE_CERTIFICATE_VERIFY: // = 9,    //Verify server certificate and goto SSLSTATE_CERTIFICATE_VERIFIED
        break;

    case SSLSTATE_CERTIFICATE_VERIFIED: //=10,   //Certificate verified. Go to SSLSTATE_CLIENT_KEYEXCHANGE.
        break;

    case SSLSTATE_CERTIFICATE_ACCEPTING: //=11,  //Wait for application to accept questionable certificate.
        break;

    case SSLSTATE_CERTIFICATE_REJECTED: //=12,   //Bad certificate rejected. Goto SSLSTATE_ABORTING.
        break;

    case SSLSTATE_CERTIFICATE_EXPIRED: //= 13,   //Certificate expired. Goto SSLSTATE_ABORTING.
        break;

    case SSLSTATE_CERTIFICATE_ACCEPTED: //=15,   //Certificate accepted by App, goto SSLSTATE_CLIENT_KEYEXCHANGE.
        break;

    case SSLSTATE_CLIENT_KEYEXCHANGE: // = 16,   //Send ClientKeyExchange & goto SSLSTATE_CLIENT_FINISH1.
        //Server finished the server hello messages and all other messages before server hello done
        if (pParams->nNetOutSize == 0) break;
#ifdef SSL_TEST_TRACE
        ret1 |= pParams->nNetOutSize - sizeof(gTrace2);
        ret1 |= memcmp(gTrace2, pParams->pNetOutData, sizeof(gTrace1));
        ret |= ret1;
        ASSERT(ret == 0);
#endif //SSL_TEST_TRACE
        break;

    case SSLSTATE_SERVER_FINISH1: //     = 17,   //Wait for ServerFinish & goto SSLSTATE_CLIENT_FINISH2.
        break;

    case SSLSTATE_CLIENT_FINISH1: //     = 18,   //Send ChangeCipher, Finish & goto SSLSTATE_SERVER_FINISH2
        break;

    case SSLSTATE_CLIENT_FINISH2: //     = 19,   //Send ChangeCipher, Finish & goto SSLSTATE_HANDSHAKE_DONE
        break;

    case SSLSTATE_SERVER_FINISH2: //     = 20,   //Wait for ServerFinish & goto SSLSTATE_HANDSHAKE_DONE.
        break;

    case SSLSTATE_HANDSHAKE_DONE: //     = 21,   //Verify every thing OK & goto SSLSTATE_CONNECTED, else
        break;

    case SSLSTATE_CONNECTED: //          = 32,   //We can now exchange application data encrypted.
        break;

    case SSLSTATE_DISCONNECT: //         = 48,   //App tells us to initiate a disconnect sequence.
        break;

    case SSLSTATE_DISCONNECTING: //      = 49,   //We were told by the server to disconnect. Tell App to disconnect
        break;

    case SSLSTATE_DISCONNECTED: //       = 50,   //App tells us TCP disconnected. Cleanup and goto SSLSTATE_UNCONNECTED
        break;

    case SSLSTATE_ABORTING: //           = 51,   //Notify server we are aborting a failed connection, then goto SSLSTATE_ABORTED
        break;

    case SSLSTATE_ABORTED: //            = 52,   //Failed connection aborted. App disconnect TCP and goto SSLSTATE_DISCONNECTED
        break;

    default:
        printf("**** L%d Wrong State %d\r\n*************", __LINE__, eStatus);
        break;
    }

    if (pParams->nNetOutSize > 0)
    {
        DumpBinary(
            pParams->pNetOutData,
            pParams->nNetOutSize,
            "Server Send to Client"
            );
    }

    return ret;
}
