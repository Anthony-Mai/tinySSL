#ifndef _SERVERMSG_H_INCLUDED_6_28_2014_
#define _SERVERMSG_H_INCLUDED_6_28_2014_


//forward declarations
struct SSL;


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

uint CreateServerHelloMsg(
    struct SSL* pSSL,
    uchar*  pMsgBuff,
    uint   nBuffSize
    );

uint CreateHelloRequestMsg(
    struct SSL* pSSL,
    uchar*      pMsgBuff,
    uint        nBuffSize
    );

uint ParseClientKeyExchange(
    struct SSL*     pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
    );

uint ParseCertificateVerify(
    struct SSL*     pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
    );

uint ParseClientChangeCipherSpec(
    struct SSL*     pSSL,
    const uchar*    pMsg,
    uint            nMsgSize
    );

uint VerifyClientMAC(
    struct SSL*     pSSL,
    uchar           cMsgType,   //Content Type. e.g., CONTENT_HANDSHAKE
    const uchar*    pMsg,
    uint*           pSize
);


uint CreateServerChangeCipherMsg(
    struct SSL* pSSL,
    uchar*  pMsgBuff,
    uint   nBuffSize
    );


uint CreateServerFinishedMsg(
    struct SSL* pSSL,
    uchar*      pMsgBuff,
    uint        nBuffSize
    );


#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _SERVERMSG_H_INCLUDED_6_28_2014_
