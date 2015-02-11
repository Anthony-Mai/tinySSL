#ifndef _CLIENTMSG_H_INCLUDED_6_17_2004_
#define _CLIENTMSG_H_INCLUDED_6_17_2004_


//Forward declaration
struct  SSL;


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

uint CreateClientHelloMsg(
    struct SSL* pSSL,
    uchar*  pMsgBuff,
    uint   nBuffSize
    );

uint CreateClientKeyExchangeMsg(
    struct SSL* pSSL,
    uchar*  pMsgBuff,
    uint   nBuffSize
    );

uint CreateChangeCipherSpecMsg(
    struct SSL* pSSL,
    uchar*  pMsgBuff,
    uint   nBuffSize
    );

uint CreateClientFinishedMsg(
    struct SSL* pSSL,
    uchar*  pMsgBuff,
    uint   nBuffSize
    );

uint VerifyServerMAC(
    struct SSL*     pSSL,
    uchar       cMsgType,   //Content Type. e.g., CONTENT_HANDSHAKE
    const uchar*    pMsg,
    uint*  pSize
);


#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _CLIENTMSG_H_INCLUDED_6_17_2004_
