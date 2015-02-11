#ifndef _RC4_H_INCLUDED_6_27_2014_
#define _RC4_H_INCLUDED_6_27_2014_


//#define TEST_RC4    //Define this to perform algorithm consistency check.


typedef struct RC4
{      
    uchar state[256];       
    uchar x;        
    uchar y;
} RC4;


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#ifdef TEST_RC4
int rc4Test();
#endif //TEST_RC4

void RC4Init(RC4* pCtx, const uchar* pKey, uint nKeyLen);
void RC4Code(RC4* pCtx, uchar* pData, uint nDataLen);

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //#ifndef _RC4_H_INCLUDED_6_27_2014_
