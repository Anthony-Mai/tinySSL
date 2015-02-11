#ifndef _SSL_H_INCLUDED_6_28_2014_
#define _SSL_H_INCLUDED_6_28_2014_


typedef enum
{
    SSLSTATE_RESET              = 0,    //Reset everything and then go to SSLSTATE_INITIALIZED.
    SSLSTATE_INITIALIZED        = 1,    //Just initialized. Nothing happened yet.
    SSLSTATE_UNCONNECTED        = 2,    //The "RESET" state after a successful or failed connection.
    SSLSTATE_TCPCONNECTED       = 3,    //Application tells us TCP connected. This triggers handshake.
    SSLSTATE_HANDSHAKE_BEGIN    = 4,    //Initialize HandShake & goto SSLSTATE_CLIENT_HELLO

    SSLSTATE_HELLO_REQUEST      = 7,    //Initiate a server hello request message
    SSLSTATE_CLIENT_HELLO       = 8,    //Send out ClientHello & goto SSLSTATE_SERVER_HELLO
    SSLSTATE_CLIENT_CERTREQUEST = 9,    //Server can set nInXData = non-zero to request client certificate.

    SSLSTATE_SERVER_HELLO       =16,    //Wait ServerHello, if reuse SessionID, goto SSLSTATE_SERVER_FINISH1, else goto SSLSTATE_SERVER_HELLO_DONE
    SSLSTATE_SERVER_CERTIFICATE =17,    //Wait Server Certificate, then go to SSLSTATE_SERVER_HELLO_DONE
    SSLSTATE_SERVER_CERTREQUEST =18,    //Certificate request received from server, Wait ServerHelloDone & goto SSLSTATE_CERTIFICATE_REQUEST
    SSLSTATE_SERVER_HELLO_DONE  =19,    //Wait ServerHelloDone & goto SSLSTATE_CERTIFICATE_VERIFY.

    SSLSTATE_CERTIFICATE_REQUEST =20,   //Server asked the client to supply a certificate. Go to SSLSTATE_CERTIFICATE_REQUESTING to tell application.
    SSLSTATE_CERTIFICATE_REQUESTING=21, //Application asked to supply a client certificate and goto SSLSTATE_CERTIFICATE_SUPPLIED, or fall to SSLSTATE_CERTIFICATE_NOTGIVEN
    SSLSTATE_CERTIFICATE_NOTGIVEN=22,   //In SSLSTATE_CERTIFICATE_REQUESTING, App fails to give us certificate. Goto SSLSTATE_ABORTING.
    SSLSTATE_CERTIFICATE_SUPPLIED=23,   //In SSLSTATE_CERTIFICATE_REQUESTING, App supplied it and set SSLSTATE_CERTIFICATE_SUPPLIED. Go to SSLSTATE_CERTIFICATE_VERIFY

    SSLSTATE_CERTIFICATE_VERIFY = 24,   //Verify server certificate and goto SSLSTATE_CERTIFICATE_VERIFIED
    SSLSTATE_CERTIFICATE_VERIFIED=25,   //Certificate verified. Go to SSLSTATE_CLIENT_KEYEXCHANGE.
    SSLSTATE_CERTIFICATE_ACCEPTING=26,  //Wait for application to accept questionable certificate. nOutXData carries the HCERT. Default goes to SSLSTATE_CERTIFICATE_REJECTED
    SSLSTATE_CERTIFICATE_REJECTED=27,   //Bad certificate rejected. Goto SSLSTATE_ABORTING.
    SSLSTATE_CERTIFICATE_EXPIRED= 28,   //Certificate expired. Goto SSLSTATE_ABORTING.
    SSLSTATE_CERTIFICATE_ACCEPTED=29,   //Certificate accepted by App, goto SSLSTATE_CLIENT_KEYEXCHANGE, or SSLSTATE_CLIENT_CERTIFICATE first

    SSLSTATE_CLIENT_CERTIFICATE = 32,   //Send the client certificate message to server and go to SSLSTATE_CLIENT_KEYEXCHANGE
    SSLSTATE_CLIENT_KEYEXCHANGE = 33,   //Send ClientKeyExchange & goto SSLSTATE_CLIENT_FINISH1, or SSLSTATE_CLIENT_VALIDATE first
    SSLSTATE_CLIENT_VALIDATE    = 34,   //Send Client certificate verify message & goto SSLSTATE_CLIENT_FINISH1

    SSLSTATE_SERVER_FINISH1     = 40,   //Wait for ServerFinish & goto SSLSTATE_CLIENT_FINISH2.
    SSLSTATE_CLIENT_FINISH1     = 41,   //Send ChangeCipher, Finish & goto SSLSTATE_SERVER_FINISH2
    SSLSTATE_CLIENT_FINISH2     = 42,   //Send ChangeCipher, Finish & goto SSLSTATE_HANDSHAKE_DONE
    SSLSTATE_SERVER_FINISH2     = 43,   //Wait for ServerFinish & goto SSLSTATE_HANDSHAKE_DONE.
    SSLSTATE_HANDSHAKE_DONE     = 48,   //Verify every thing OK & goto SSLSTATE_CONNECTED, else

    SSLSTATE_CONNECTED          = 64,   //We can now exchange application data encrypted.
    SSLSTATE_DISCONNECT         = 66,   //App tells us to initiate a disconnect sequence.
    SSLSTATE_DISCONNECTING      = 67,   //We were told by the server to disconnect. Tell App to disconnect
    SSLSTATE_DISCONNECTED       = 68,   //App tells us TCP disconnected. Cleanup and goto SSLSTATE_UNCONNECTED
    SSLSTATE_ABORT              = 70,   //We fall into a fatal error processing incoming message. So bail out.
    SSLSTATE_ABORTING           = 71,   //Notify server we are aborting a failed connection, then goto SSLSTATE_ABORTED
    SSLSTATE_ABORTED            = 72,   //Failed connection aborted. App disconnect TCP and goto SSLSTATE_DISCONNECTED
    SSLSTATE_ERROR              = -1    //Any other errors.
} SSL_STATE;


typedef enum
{
    SSL_OK                  = 0,
    SSL_RESULT_INVALID      = 1,
    SSL_RESULT_NOT_APPLY    = 2,
    SSL_ERROR_GENERIC       = -1,
    SSL_ERROR_PARSE         = -2,
    SSL_ERROR_TIMEOUT       = -3,
    SSL_ERROR_MEMORY        = -4,
    SSL_ERROR_NOTREADY      = -5,
    SSL_ERROR_CERTIFICATE_EXISTS = -6,
    SSL_ERROR_CERTIFICATE_BAD   = -7,
    SSL_ERROR_BUFFER_FULL   = -8,
    SSL_ERROR_LIMIT32       = 0xFFFF0000    //Forcing 32 bits int for enum
} SSL_RESULT;


//Forward Declarations
struct  SSL;
struct CIPHERSET;

typedef struct SSL* HSSL;
typedef struct CIPHERSET CIPHERSET;

#define     IN      //Input parameter
#define     OUT     //Output parameter
#define     MDD     //Modifiable parameter

typedef union {
    void *          ptr;
    unsigned int    data;
} XDATA;


typedef struct CERTKEY_INFO
{
    struct CERTKEY_INFO*    pPrev;
    struct CERTKEY_INFO*    pNext;
    uint            nKeyLengthBits;
    const uchar*    pCertificate;
    const uchar*    pPublicKey;
    const uchar*    pPrivateKey;
} CERTKEY_INFO;


typedef struct SSL_PARAMS
{
    MDD SSL_STATE               eState;         //State of the SSL engine.
    IN  unsigned int            nUnixTime;      //Seconds since EPOCH, Jan. 01, 1970 12:00am UTC
    IN  XDATA                   nInXData;       //Undefined data application sent to SSL
    OUT XDATA                   nOutXData;      //Undefined data SSL engine send to caller
    MDD const unsigned char*    pNetInData;     //Incoming network data pointer
    MDD unsigned int            nNetInSize;     //Incoming network data size.
    IN  const unsigned char*    pAppInData;     //Application data sent into SSL and to server
    MDD unsigned int            nAppInSize;     //Size of Application data into SSL then server
    OUT const unsigned char*    pNetOutData;    //Outgoing network data pointer
    OUT unsigned int            nNetOutSize;    //Outgoing network data size
    MDD unsigned char*          pAppOutData;    //Buffer to receive Application Data which came from server
    MDD unsigned int            nAppOutSize;    //Buffer size, and size of data sent to application, from server
} SSL_PARAMS;


typedef void* (*SSL_MALLOC)(unsigned int nSize);
typedef void  (*SSL_FREE)(void* pMemBlock);

//Application provided Pseudo Random Number Generator (PRNG) function.
//Application must initialize and seed the PRNG first.
typedef unsigned int (*SSL_RANDOM)();

//The pUserData will be interpreted as a HSSL, SSL Handle.
typedef SSL_RESULT (*SSL_CALLBACK)(SSL_PARAMS* pParam, HSSL pUserData);


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

//This function must be called preceeding any other SSL calls.
//Application can optionally provide memory allocating and free functions.
SSL_RESULT SSL_Initialize(
    SSL_MALLOC      pMallocFunc,
    SSL_FREE        pFreeFunc,
    SSL_RANDOM      pRandomFunc,
    const CIPHERSET* pCipherSet,
    unsigned int    nSvrMsgSize,
    unsigned int    nAppMsgSize
    );

//This function is used to add trusted root certificates. Selected *.cer
//files dumped from the InternetExplorer root certificates are OK, as long
//as the associated entities can continue to be trusted.
SSL_RESULT SSL_AddRootCertificate(const unsigned char* pCert, unsigned int nLen, unsigned int nUnixTime);

//This function is used to add CRL (Certificate RevocationList). Application
//should obtain current (up to date) CRLs from the internet. One source is:
//  http://www.geotrust.com/resources/crls/index.htm
SSL_RESULT SSL_AddCRL(unsigned char* pCRL, unsigned int nLen);

//Create an instance of HSSL to be used in a HTTPS connection session.
SSL_RESULT SSL_Create(HSSL* pHSSL, CERTKEY_INFO* pCertKey);

//Destroy an instance of HSSL. The instance should no longer be used.
SSL_RESULT SSL_Destroy(HSSL hSSL);

//The filtering function that carries out all SSL operations.
SSL_RESULT SSL_Process(SSL_PARAMS* pParam, HSSL pUserData);

//The cleanup function that should be the last SSL function to be called.
SSL_RESULT SSL_Cleanup();


#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _SSL_H_INCLUDED_6_28_2014_
