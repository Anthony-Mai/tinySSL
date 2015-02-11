#ifndef _SSLSERVER_H_INCLUDED_6_28_2014_
#define _SSLSERVER_H_INCLUDED_6_28_2014_


#include "ssl.h"



#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

//Application must fill out this data to over-ride the default server key.
extern CERTKEY_INFO gServerCertKey;

//The filtering function that carries out all SSL operations on server
SSL_RESULT SSL_Server(SSL_PARAMS* pParam, HSSL pUserData);

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _SSLSERVER_H_INCLUDED_6_28_2014_
