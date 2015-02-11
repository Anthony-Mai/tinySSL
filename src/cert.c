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
*  File Name:       cert.c
*
*  Description:     X.509 digital certificate parsing and processing.
*
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         6/27/2014 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "cert.h"

#include "cipher.h"
#include "BN.h"
#include "sha256.h"


#define MD5 CTX
#define SHA CTX

#define MD5_SIZE                    16
#define SHA1_SIZE                   20
#define SHA256_SIZE                 32


#define VERSION_V1      0   //Default is V1
#define VERSION_V2      1
#define VERSION_V3      2


#define HASH_NONE           0
#define HASH_MD2_WITH_RSA   1
#define HASH_MD4_WITH_RSA   2
#define HASH_MD5_WITH_RSA   3
#define HASH_SHA1_WITH_RSA  4
#define HASH_SHA256_WITH_RSA 5


// Tag classes
#define CLASS_MASK          0xC0    // Bits 8 and 7
#define CLASS_UNIVERSAL     0x00    // 0 = Universal (defined by ITU X.680)
#define CLASS_APPLICATION   0x40    // 1 = Application
#define CLASS_CONTEXT       0x80    // 2 = Context-specific
#define CLASS_PRIVATE       0xC0    // 3 = Private

// Encoding type
#define FORM_MASK           0x20    // Bit 6
#define FORM_PRIMITIVE      0x00    // 0 = primitive
#define FORM_CONSTRUCTED    0x20    // 1 = constructed

// Universal tags
#define TAG_MASK		    0x1F    // Bits 5 - 1
#define TAG_ZERO            0x00    // Constructed [0]
#define TAG_EOC             0x00    //  0: End-of-contents octets
#define TAG_BOOLEAN         0x01    //  1: Boolean
#define TAG_INTEGER         0x02    //  2: Integer
#define TAG_BITSTRING       0x03    //  2: Bit string
#define TAG_OCTETSTRING     0x04    //  4: Byte string
#define TAG_NULLTAG         0x05    //  5: NULL
#define TAG_OID             0x06    //  6: Object Identifier
#define TAG_OBJDESCRIPTOR   0x07    //  7: Object Descriptor
#define TAG_EXTERNAL        0x08    //  8: External
#define TAG_REAL            0x09    //  9: Real
#define TAG_ENUMERATED      0x0A    // 10: Enumerated
#define TAG_EMBEDDED_PDV    0x0B    // 11: Embedded Presentation Data Value
#define TAG_UTF8STRING      0x0C    // 12: UTF8 string
#define TAG_SEQUENCE        0x10    // 16: Sequence/sequence of
#define TAG_SET             0x11    // 17: Set/set of
#define TAG_NUMERICSTRING   0x12    // 18: Numeric string
#define TAG_PRINTABLESTRING 0x13    // 19: Printable string (ASCII subset)
#define TAG_T61STRING       0x14    // 20: T61/Teletex string
#define TAG_VIDEOTEXSTRING  0x15    // 21: Videotex string
#define TAG_IA5STRING       0x16    // 22: IA5/ASCII string
#define TAG_UTCTIME         0x17    // 23: UTC time
#define TAG_GENERALIZEDTIME 0x18    // 24: Generalized time
#define TAG_GRAPHICSTRING   0x19    // 25: Graphic string
#define TAG_VISIBLESTRING   0x1A    // 26: Visible string (ASCII subset)
#define TAG_GENERALSTRING   0x1B    // 27: General string
#define TAG_UNIVERSALSTRING 0x1C    // 28: Universal string
#define TAG_BMPSTRING       0x1E    // 30: Basic Multilingual Plane/Unicode string


#define INTEGER_TAG     (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_INTEGER)
#define OID_TAG         (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_OID)
#define SEQUENCE_TAG    (CLASS_UNIVERSAL|FORM_CONSTRUCTED|TAG_SEQUENCE)
#define NULL_TAG        (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_NULLTAG)
#define BITSTRING_TAG   (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_BITSTRING)
#define SET_TAG         (CLASS_UNIVERSAL|FORM_CONSTRUCTED|TAG_SET)
#define PRINTABLE_STRING_TAG    (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_PRINTABLESTRING)
#define IA5STRING_TAG   (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_IA5STRING)

#define UTCTIME_TAG     (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_UTCTIME)
#define GENTIME_TAG     (CLASS_UNIVERSAL|FORM_PRIMITIVE|TAG_GENERALIZEDTIME)

#define MAX_RSA_KEY_SIZE    2048

typedef enum
{
    OID_UNKNOWN         = 0,
    OID_RSA             = 1,
    OID_EMAIL           = 2,
    OID_EMAIL2          = 3,

    OID_HASH_MD2_RSA    = 8,
    OID_HASH_MD4_RSA    = 9,
    OID_HASH_MD5_RSA    =10,
    OID_HASH_SHA1_RSA   =11,
    OID_HASH_SHA256_RSA =12,

    OID_NAME_COMMON     = 64,
    OID_NAME_ORG        = 65,
    OID_NAME_UNIT       = 66,
    OID_NAME_LOCAL      = 67,
    OID_NAME_STATE      = 68,
    OID_NAME_COUNTRY    = 69,

    OID_DIGEST_MD2      = 72,
    OID_DIGEST_MD4      = 73,
    OID_DIGEST_MD5      = 74,
    OID_DIGEST_SHA1     = 75,
    OID_DIGEST_SHA256   = 76
} OID;


typedef struct CTX {
    uint    data[24];
} CTX;


typedef struct ASN1ITEM
{
    uint    nType;
    uint    iClass;
    uint    iForm;
    uint    iTag;
    uint    nSize;
} ASN1ITEM;


typedef struct X509NAME
{
    uchar   md5digest[MD5_SIZE];    //Digest the whole thing
    uchar   md5digest2[MD5_SIZE];   //Digest just localName, OrgName and OrgUnit.
    char    emailaddress[32];
    char    CommonName[64];         //commonName is most used identifying string
    char    orgUnit[64];
    char    orgName[64];
    char    localName[32];
    char    state[16];
    char    country[16];
} X509NAME;


// See this web site for Julian date info:
//  http://scienceworld.wolfram.com/astronomy/JulianDate.html
typedef struct DATETIME
{
    uint    second;     // Julian second
    uint    day;        // Julian day
} DATETIME;


typedef struct CERT
{
    struct CERT* prev;          //These two pointers are used to easily chain
    struct CERT* next;          //a number of certificates into linked list.
    struct CERT* pRootCert;     //Pointer to certificate of the signer.
    uint        version;        //0:V1, 1:V2, 2:V3. Default: V1
    uint        status;         //Certificate Status
    uint        hashAlgorithm;  //1:HASH_MD5_WITH_RSA, 2:HASH_SHA1_WITH_RSA
    uint        serialLen;      //Length of the serial number, in bytes
    uint        pubKeyLen;      //Length of public key, in bytes, not bits!
    uint        pubExp;
    uint        receiveTime;    //The UNIX time when the X.509 certificate is received.
    uint        validTime;      //The UNIX time how longer will it be valid. Not used.
    DATETIME    enableTime;     //Julian date of effective date
    DATETIME    expireTime;     //Julian date of expiration date
    uchar       serialNum[20];
    uchar       digest[20];     //Maximum digest size 20 bytes for SHA-1
    X509NAME    name;
    X509NAME    issuer;
    uchar       pubKey[MAX_RSA_KEY_SIZE/8];
    uchar       signature[MAX_RSA_KEY_SIZE/8];
} CERT;


typedef struct OIDDATA
{
    OID     oid;
    uint    nDataSize;
    uchar   data[16];
} OIDDATA;


OIDDATA gOIDs[] =
{
    {               //OID = 06 09 2A 86 48 86 F7 0D 01 01 01
        OID_RSA,    //Comment = PKCS #1
        9,          //Description = rsaEncryption (1 2 840 113549 1 1 1)
        {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}
    },
    {                       //OID = 06 09 2A 86 48 86 F7 0D 01 01 02
        OID_HASH_MD2_RSA,   //Comment = PKCS #1
        9,                  //Description = md2withRSAEncryption (1 2 840 113549 1 1 2)
        {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02}
    },
    {                       //OID = 06 09 2A 86 48 86 F7 0D 01 01 03
        OID_HASH_MD4_RSA,   //Comment = PKCS #1
        9,                  //Description = md4withRSAEncryption (1 2 840 113549 1 1 3)
        {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02}
    },
    {                       //OID = 06 09 2A 86 48 86 F7 0D 01 01 04
        OID_HASH_MD5_RSA,   //Comment = PKCS #1
        9,                  //Description = md5withRSAEncryption (1 2 840 113549 1 1 4)
        {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04}
    },
    {                       //OID = 06 09 2A 86 48 86 F7 0D 01 01 05
        OID_HASH_SHA1_RSA,  //Comment = PKCS #1
        9,                  //Description = sha1withRSAEncryption (1 2 840 113549 1 1 5)
        {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05}
    },
    {                       //OID = 06 09 2A 86 48 86 F7 0D 01 01 0B
        OID_HASH_SHA256_RSA,//Comment = PKCS #1
        9,                  //Description = sha1withRSAEncryption (1 2 840 113549 1 1 11)
        {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}
    },
    {                       //OID = 06 03 55 04 03
        OID_NAME_COMMON,    //Comment = X.520 id-at (2 5 4)
        3,                  //Description = commonName (2 5 4 3)
        {0x55, 0x04, 0x03}
    },
    {                           //OID = 06 03 55 04 0A
        OID_NAME_ORG,  //Comment = X.520 id-at (2 5 4)
        3,                      //Description = organizationName (2 5 4 10)
        {0x55, 0x04, 0x0A}
    },
    {                               //OID = 06 03 55 04 0B
        OID_NAME_UNIT, //Comment = X.520 id-at (2 5 4)
        3,                          //Description = organizationalUnitName (2 5 4 11)
        {0x55, 0x04, 0x0B}
    },
    {                           //OID = 06 03 55 04 07
        OID_NAME_LOCAL,      //Comment = X.520 id-at (2 5 4)
        3,                      //Description = localityName (2 5 4 7)
        {0x55, 0x04, 0x07}
    },
    {                       //OID = 06 03 55 04 08
        OID_NAME_STATE,     //Comment = X.520 id-at (2 5 4)
        3,                  //Description = stateOrProvinceName (2 5 4 8)
        {0x55, 0x04, 0x08}
    },
    {                       //OID = 06 03 55 04 06
        OID_NAME_COUNTRY,   //Comment = X.520 id-at (2 5 4)
        3,                  //Description = countryName (2 5 4 6)
        {0x55, 0x04, 0x06}
    },
    {                       //OID = 06 08 2A 86 48 86 F7 0D 02 02
        OID_DIGEST_MD2,     //Comment = RSADSI digestAlgorithm
        8,                  //Description = md2 (1 2 840 113549 2 2)
        {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x02}
    },
    {                       //OID = 06 08 2A 86 48 86 F7 0D 02 04
        OID_DIGEST_MD4,     //Comment = RSADSI digestAlgorithm
        8,                  //Description = md4 (1 2 840 113549 2 4)
        {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x04}
    },
    {                       //OID = 06 08 2A 86 48 86 F7 0D 02 05
        OID_DIGEST_MD5,     //Comment = RSADSI digestAlgorithm
        8,                  //Description = md5 (1 2 840 113549 2 5)
        {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05}
    },
    {                       //OID = 06 05 2B 0E 03 02 1A
        OID_DIGEST_SHA1,    //Comment = OIW
        5,                  //Description = sha1 (1 3 14 3 2 26)
        {0x2B, 0x0E, 0x03, 0x02, 0x1A}
    },
    {                       //OID = 06 09 60 86 48 01 65 03 04 02 01
        OID_DIGEST_SHA256,  //Comment = SHA-256 nistAlgorithms
        9,                  //Description = sha-256 (2.16.840.1.101.3.4.2.1)
        {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}
    },
    {                       //OID = 06 09 2A 86 48 86 F7 0D 01 09 01
        OID_EMAIL,   //Comment = PKCS #9.  Deprecated, use an altName extension instead
        9,                  //Description = emailAddress (1 2 840 113549 1 9 1)
        {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01}
    },
    {                       //OID = 06 0A 2B 06 01 04 01 2A 02 0B 02 01
        OID_EMAIL2,  //Comment = Unknown
        10,                 //Description = emailAddress (1 3 6 1 4 1 42 2 11 2 1)
        {0x2B, 0x06, 0x01, 0x04, 0x01, 0x2A, 0x02, 0x0B, 0x02, 0x01}
    },
    {
        OID_UNKNOWN,
        0,
        {0x00}
    }
};


OID GetOID(const uchar* pMsg, uint nMsgSize)
{
    OIDDATA*    pOID;

    for (pOID = gOIDs; pOID->oid != OID_UNKNOWN; pOID++)
    {
        if (nMsgSize != pOID->nDataSize)
        {
            continue;
        }

        if (0 == memcmp(pMsg, pOID->data, nMsgSize))
        {
            return pOID->oid;
        }
    }

    return OID_UNKNOWN;
}


uint SetOID(uchar* pBuff, OID oid)
{
    OIDDATA*    pOID;

    for (pOID = gOIDs; pOID->oid != OID_UNKNOWN; pOID++)
    {
        if (oid == pOID->oid)
        {
            memcpy(pBuff, pOID->data, pOID->nDataSize);

            return pOID->nDataSize;
        }
    }

    return 0;
}


static FMalloc gfMalloc = NULL;
static FFree   gfFree   = NULL;
static const CIPHERSET* gpCipherSet = NULL;

static CERT* gpRootCerts = NULL;
static CERT* gpMidCerts  = NULL;

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

extern X509NAME gTempCA; //Expose this variable to other libraries.
X509NAME gTempCA; //An instance that some one can used without declaring their own.

#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


//Function Protocol Declarations
static uint GetASN1Item(ASN1ITEM* pItem, const uchar* pMsg);
uint ParseTBS(CERT* pCert, const uchar* pMsg, uint nMsgSize);
static uint ParseX509Name(X509NAME* pName, const uchar* pMsg, uint nMsgSize);
static uint ParseUTCTime(DATETIME* pTime, const uchar* pMsg, uint nMsgSize);
static uint ParseGENTime(DATETIME* pTime, const uchar* pMsg, uint nMsgSize);
static uint VerifySignature(const CERT* pCert, const CERT* pSigner);
static uint NotSameX509Name(const X509NAME* pName1, const X509NAME* pName2);
static CERT* FindCert(const X509NAME* pX509Name, CERT** ppIntermedateCerts);


/******************************************************************************
* Function:     InsertCert
*
* Description:  Insert a certificate into the certificate depository.
*
* Returns:      Pointer to the certificate inserted if OK. else NULL.
******************************************************************************/
CERT* InsertCert
(
    CERT*   pCert,
    CERT**  ppMidCerts
)
{
    CERT*   pCert2;

    // Sanity check.
    if (NULL == pCert)
    {
        return NULL;
    }

    if (ppMidCerts == NULL)
    {
        ppMidCerts = &gpMidCerts;
    }

    //First make sure we do not already have the certificate in the deposit.
    pCert2 = FindCert(&(pCert->name), ppMidCerts);
    if (NULL != pCert2)
    {
        //If there was one with the same name. Delete the old one, unless the
        //old one was a root certificate.
        if (pCert2->status & CS_ROOT)
        {
            //We can not flush out our root certificate! Especially not by a
            //self-signed certificate coming from the network.
            return NULL;    //Tell caller the certificate not inserted.
        }
        else
        {
            //Get rid of the old certificate and insert the new one.
            //DestroyCert(DeleteCert(pCert2, ppMidCerts));

            //The old and new certificate has the same name but are they exactly identical?
            if (memcmp(pCert->pubKey, pCert2->pubKey, pCert->pubKeyLen))
            {
                //We have a problem, the two certs have same name but are different
                assert(0);
            }
            else
            {
                //We are OK.
            }
            
            return NULL;
        }
    }

    if (pCert->status & CS_ROOT)
    {
        // We are suppose to insert it as a root certificate.
        if (NULL == gpRootCerts)
        {
            gpRootCerts = pCert;
            pCert->prev = gpRootCerts;
            pCert->next = gpRootCerts;
        }
        else
        {
            pCert->prev = gpRootCerts->prev;
            pCert->next = gpRootCerts;
            pCert->prev->next = pCert;
            pCert->next->prev = pCert;
        }
    }
    else
    {
        // We are suppose to insert it as a intermedia certificate.
        if (NULL == *ppMidCerts)
        {
            *ppMidCerts = pCert;
            pCert->prev = *ppMidCerts;
            pCert->next = *ppMidCerts;
        }
        else
        {
            pCert->prev = (*ppMidCerts)->prev;
            pCert->next = *ppMidCerts;
            pCert->prev->next = pCert;
            pCert->next->prev = pCert;
        }
    }

    return pCert;
}


/******************************************************************************
* Function:     DeleteCert
*
* Description:  Remove a certificate from the certificate depository. The
*               certificate is NOT destroyed so the caller still has to call
*               DestroyCert().
*
* Returns:      Pointer to the certificate removed if successful. Else NULL.
******************************************************************************/
CERT* DeleteCert
(
    CERT*   pCert,
    CERT**  ppMidCerts
)
{
    CERT* pCert2 = NULL;

    if (NULL == pCert)
    {
        return NULL;
    }

    if (ppMidCerts == NULL)
    {
        ppMidCerts = &gpMidCerts;
    }

    if (pCert == *ppMidCerts)
    {
        pCert2 = *ppMidCerts;
        *ppMidCerts = pCert2->next;
        if (*ppMidCerts == pCert2)
        {
            *ppMidCerts = NULL;
        }
    }
    else if (pCert == gpRootCerts)
    {
        pCert2 = gpRootCerts;
        gpRootCerts = pCert2->next;
        if (gpRootCerts == pCert2)
        {
            gpRootCerts = NULL;
        }
    }
    else
    {
        // We need to verify that pCert is within the deposit of either
        // gpRootCerts or gpMidCerts.
        pCert2 = pCert;
        while (NULL != pCert2)
        {
            if ((pCert2 == gpRootCerts) || (pCert2 == *ppMidCerts))
            {
                break;
            }

            pCert2 = pCert2->next;
            if (pCert2 == pCert)
            {
                pCert2 = NULL;
                break;
            }
        }
    }

    if (NULL == pCert2)
    {
        return NULL;
    }

    //Unhook the certificate.
    pCert->next->prev = pCert->prev;
    pCert->prev->next = pCert->next;

    return pCert;
}


/******************************************************************************
* Function:     NotSameX509Name
*
* Description:  Determine if the two X509 name entities are exactly same or not.
*
* Returns:      None zero if the name entities do not match. Zero if matches.
******************************************************************************/
uint NotSameX509Name
(
    const X509NAME* pName1,
    const X509NAME* pName2
)
{
    return memcmp(pName1->md5digest, pName2->md5digest, sizeof(pName1->md5digest));
}


/******************************************************************************
* Function:     FindCert
*
* Description:  Find a certificate that matches the given X509 name entity.
*
* Returns:      Pointer to the certificate if found. Else NULL.
******************************************************************************/
CERT* FindCert
(
    const X509NAME* pX509Name,
    CERT** ppMidCerts
)
{
    CERT* pCert;

    // First look among root certificates.
    pCert = gpRootCerts;
    while (NULL != pCert)
    {
        if (0 == NotSameX509Name(&(pCert->name), pX509Name))
        {
            return pCert;
        }

        pCert = pCert->next;

        if (pCert == gpRootCerts)
        {
            break;
        }
    }

    // Then look among imtermediate certificates.
    if (ppMidCerts == NULL)
    {
        ppMidCerts = &gpMidCerts;
    }

    pCert = *ppMidCerts;
    while (NULL != pCert)
    {
        if (0 == NotSameX509Name(&(pCert->name), pX509Name))
        {
            return pCert;
        }

        pCert = pCert->next;

        if (pCert == *ppMidCerts)
        {
            break;
        }
    }

    return NULL;
}


/******************************************************************************
* Function:     EnumCerts
*
* Description:  Enumerate the certificates in the certificate deposit, first
*               root certificates and then non-root certificates. The callback
*               function tells us to stop when it returns a non-zero value.
*
* Returns:      Number of certificates enumerated when we stop.
******************************************************************************/
uint EnumCerts
(
    ENUMCERT_FUNC   pEnumFunc,
    void*           pUserData
)
{
    uint    nTotal = 0;
    CERT*   pCert;
    CERT**  ppMidCerts = NULL;

    if (ppMidCerts == NULL)
    {
        ppMidCerts = &gpMidCerts;
    }

    // First enumerate root certificates.
    pCert = gpRootCerts;
    while (NULL != pCert)
    {
        nTotal ++;
        if (0 != pEnumFunc(pCert, pUserData))
        {
            //The application tells us do not enumerate more. So return.
            return nTotal;
        }

        pCert = pCert->next;

        if (pCert == gpRootCerts)
        {
            break;
        }
    }

    // Then look among imtermediate certificates.
    pCert = *ppMidCerts;
    while (NULL != pCert)
    {
        nTotal ++;
        if (0 != pEnumFunc(pCert, pUserData))
        {
            //The application tells us do not enumerate more. So return.
            return nTotal;
        }

        pCert = pCert->next;

        if (pCert == *ppMidCerts)
        {
            break;
        }
    }

    return nTotal;
}


/******************************************************************************
* Function:     GetASN1Item
*
* Description:  Parse to get one ASN1 tag. Note special handling for BITSTRING.
*
* Returns:      The size of the tag header, could be 2, 3, or 4 bytes.
******************************************************************************/
uint GetASN1Item
(
    ASN1ITEM*       pItem,
    const uchar*    pMsg
)
{
    uint    nParsed = 0;

    pItem->nType = *pMsg++;
    nParsed ++;

    pItem->iClass = (pItem->nType & CLASS_MASK);
    pItem->iForm  = (pItem->nType & FORM_MASK);
    pItem->iTag   = (pItem->nType & TAG_MASK);

    if (pItem->nType)
    {
        pItem->nSize = *pMsg++;
        nParsed ++;

        if (pItem->nSize & 0x80)
        {
            if (pItem->nSize == 0x81)
            {
                pItem->nSize  = *pMsg++;
                nParsed ++;
            }
            else if (pItem->nSize == 0x82)
            {
                pItem->nSize  = *pMsg++;
                pItem->nSize<<= 8;
                pItem->nSize += *pMsg++;
                nParsed += 2;
            }
        }
    }

    //Special case for BITSTRING, eat the next 0x00 byte.
    if ((pItem->nType == BITSTRING_TAG) && (0x00 == *pMsg))
    {
        pItem->nSize --;
        nParsed ++;
    }

    return nParsed;
}


/******************************************************************************
* Function:     StartCerts
*
* Description:  Set up certificate memory management functions.
*
* Returns:      None.
******************************************************************************/
void StartCerts
(
    FMalloc         pMallocFunc,
    FFree           pFreeFunc,
    const CIPHERSET* pCipherSet
)
{
    gfMalloc = pMallocFunc;
    gfFree   = pFreeFunc;
    gpCipherSet = pCipherSet;
}


/******************************************************************************
* Function:     CreateCert
*
* Description:  Create a certificate. the eStatus used should be either
*               CS_ROOT if it is to be a root certificate, or CS_UNKNOWN.
*
* Returns:      Pointer to the certificate initially created.
******************************************************************************/
CERT* CreateCert
(
    CERT_STATUS eStatus,
    uint        nUnixTime
)
{
    CERT* pCert = NULL;

    if (NULL == gfMalloc)
    {
        //Can't do anything without the malloc function.
        return NULL;
    }

    if ((eStatus != CS_ROOT) && (NULL == gpRootCerts))
    {
        //Needs to load root certificates first.
        return NULL;
    }

    pCert = (CERT*)gfMalloc(sizeof(*pCert));
    if (NULL != pCert)
    {
        memset(pCert, 0, sizeof(*pCert));

        pCert->status = eStatus;
        pCert->receiveTime = nUnixTime;
    }

    return pCert;
}


/******************************************************************************
* Function:     DestroyCert
*
* Description:  Cleanup and deallocate memory used by the certificate.
*
* Returns:      None
******************************************************************************/
void DestroyCert
(
    CERT*     pCert
)
{
    if ((NULL != pCert) && (NULL != gfFree))
    {
        gfFree(pCert);
    }
}


/******************************************************************************
* Function:     CleanupCerts
*
* Description:  Cleanup and destroy all certificates we have. Usually this is
*               done when we cleanup to quit the application.
*
* Returns:      None.
******************************************************************************/
void CleanupCerts(CERT** ppMidCerts)
{
    CERT* pCert;

    if (ppMidCerts != NULL)
    {
        while (NULL != (pCert = *ppMidCerts))
        {
            DeleteCert(pCert, ppMidCerts);
            DestroyCert(pCert);
        }
        return;
    }

    while (NULL != (pCert = gpMidCerts))
    {
        DeleteCert(pCert, NULL);
        DestroyCert(pCert);
    }
    while (NULL != (pCert = gpRootCerts))
    {
        DeleteCert(pCert, NULL);
        DestroyCert(pCert);
    }
}


/******************************************************************************
* Function:     ParseCert
*
* Description:  Parse the content of DER encoded binary X.509 (.cer) certificate
*               and put the information into a CERT.
*
* Returns:      Number of bytes parsed. Zero if the parsing failed.
******************************************************************************/
uint ParseCert
(
    CERT*           pCert,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uint            nParsed = 0;
    uint            nParseSize;
    uint            nCertSize;
    uint            nHeadSize;
    const uchar*    pHashContent;
    uint            nHashSize;
    ASN1ITEM        item;

    // First is a SEQUENCE tag that encloses the whole certificate.
    nHeadSize = GetASN1Item(&item, pMsg);
    pMsg    += nHeadSize;
    nParsed += nHeadSize;

    if ((item.nType != SEQUENCE_TAG) ||
        ((nParsed + item.nSize) != nMsgSize) )
    {
        //assert(item.nType == SEQUENCE_TAG);
        return 0;
    }

    nCertSize = item.nSize;
    pHashContent = pMsg;

    // Next is a SEQUENCE tag enclosing the TBSCertificate part.
    nHeadSize = GetASN1Item(&item, pMsg);
    pMsg    += nHeadSize;
    nParsed += nHeadSize;

    if (item.nType != SEQUENCE_TAG) {return 0;}

    nHashSize = nHeadSize + item.nSize;

    //Parse the TBSCertificate part.
    nParseSize = ParseTBS(pCert, pMsg, item.nSize);

    if (nParseSize != item.nSize) {return 0;}

    pMsg += item.nSize;
    nParsed += item.nSize;

    //Calculate the digest of the TBSCertificate part
    switch (pCert->hashAlgorithm)
    {
    case HASH_MD2_WITH_RSA:
        assert(0); //Not supported
        return 0;
        break;
    case HASH_MD4_WITH_RSA:        
        assert(0); //Not supported
        return 0;
        break;
    case HASH_MD5_WITH_RSA:
        gpCipherSet->md5.Hash(
            pHashContent,
            nHashSize,
            &(pCert->digest[sizeof(pCert->digest) - MD5_SIZE])
            );
        break;
    case HASH_SHA1_WITH_RSA:
        gpCipherSet->sha1.Hash(
            pHashContent,
            nHashSize,
            &(pCert->digest[sizeof(pCert->digest) - SHA1_SIZE])
            );
        break;
    case HASH_SHA256_WITH_RSA:
        gpCipherSet->sha256.Hash(
            pHashContent,
            nHashSize,
            &(pCert->digest[sizeof(pCert->digest) - SHA256_SIZE])
            );
        break;
    default:
        assert(0);  //Unknown hash algorithm.
        return 0;
        break;
    }

    // Following TBSCertificate is a SEQUENCE enclosing OID of hash algorithm.
    nHeadSize = GetASN1Item(&item, pMsg);
    pMsg    += nHeadSize;
    nParsed += nHeadSize;

    if (item.nType == SEQUENCE_TAG)
    {
        OID     oid = OID_UNKNOWN;
        uint    hashAlgorithm = HASH_NONE;

        //First is an OID tag identifying the hashAlgorithm
        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if (item.nType == OID_TAG)
        {
            oid = GetOID(pMsg, item.nSize);
        }
        else
        {
            //assert(item.nType == OID_TAG);
            return 0;
        }

        pMsg += item.nSize;
        nParsed += item.nSize;

        //The hashAlgorithm must match that in the TBSCertificate part.
        switch (oid)
        {
        case OID_HASH_MD2_RSA:
            hashAlgorithm = HASH_MD2_WITH_RSA;
            break;
        case OID_HASH_MD4_RSA:
            hashAlgorithm = HASH_MD4_WITH_RSA;
            break;
        case OID_HASH_MD5_RSA:
            hashAlgorithm = HASH_MD5_WITH_RSA;
            break;
        case OID_HASH_SHA1_RSA:
            hashAlgorithm = HASH_SHA1_WITH_RSA;
            break;
        case OID_HASH_SHA256_RSA:
            hashAlgorithm = HASH_SHA256_WITH_RSA;
            break;
        default:
            return 0;
            break;
        }

        if (hashAlgorithm != pCert->hashAlgorithm)
        {
            // HashAlgorithm does not match. The certificate is corrupted.
            pCert->status &= ~CS_OK;
            pCert->status |= CS_BAD;
        }

        // Following the OID is a NULL tag
        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        pMsg += item.nSize;
        nParsed += item.nSize;
    }
    else
    {
        return 0;
    }

    // Following OID of hash algorithm is the signature block
    nHeadSize = GetASN1Item(&item, pMsg);
    pMsg    += nHeadSize;
    nParsed += nHeadSize;

    if (item.nType == BITSTRING_TAG)
    {
        uint    nCopySize = item.nSize;

        if (nCopySize > sizeof(pCert->signature))
        {
            //Should not occur. If it happens it is an error condition
            //and the certificate can not be properly parsed.
            nCopySize = sizeof(pCert->signature);
        }
        memcpy(
            &(pCert->signature[sizeof(pCert->signature) - nCopySize]),
            pMsg,
            nCopySize
            );
    }
    else
    {
        return 0;
    }

    pMsg += item.nSize;
    nParsed += item.nSize;

    //All of the certificate have been parsed.
    if (nParsed == nMsgSize)
    {
        return nParsed;
    }
    else
    {
        //assert(nParsed == nMsgSize);
        return 0;
    }
}


/******************************************************************************
* Function:     ParseTBS
*
* Description:  Parse the TBSCertificate portion of the X.509 certificate.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseTBS
(
    CERT*           pCert,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uint        nParsed = 0;
    uint        nParseSize;
    uint        nHeadSize;
    ASN1ITEM    item;

    pCert->version = VERSION_V1; //Default to V1

    // 1. First tag is either the certificate sequence number, or
    // a version before the sequence.
    for (;;)
    {
        uint    nCopySize;

        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if (item.nType == (CLASS_CONTEXT | FORM_CONSTRUCTED | TAG_ZERO))
        {
            // The tag is Constructed type [0].
            // The optional version tag is present.
            nHeadSize = GetASN1Item(&item, pMsg);
            pMsg    += nHeadSize;
            nParsed += nHeadSize;

            pCert->version = *pMsg++;
            nParsed ++;

            continue;   //This is the only case that continue
        }

        if (item.nType == INTEGER_TAG)
        {
            nCopySize = item.nSize;
            if (nCopySize > sizeof(pCert->serialNum))
            {
                if (nCopySize > 32)
                {
                    //Very long serial number. Must be bogus so bail out.
                    return 0;
                }
                nCopySize = sizeof(pCert->serialNum);
            }
            memcpy(
                &(pCert->serialNum[sizeof(pCert->serialNum) - nCopySize]),
                &(pMsg[item.nSize - nCopySize]),
                nCopySize
                );
            pCert->serialLen = nCopySize;
        }
        else
        {
            //Bail out on any suspected data corruption.
            return 0;
        }

        pMsg += item.nSize;
        nParsed += item.nSize;

        break; //Always break except for the case of optional version tag
    }

    // 2. Should be a sequence containing the OID for hash algorithm
    nHeadSize = GetASN1Item(&item, pMsg);
    pMsg    += nHeadSize;
    nParsed += nHeadSize;

    if (item.nType == SEQUENCE_TAG)
    {
        OID     oid = OID_UNKNOWN;

        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if (item.nType == OID_TAG)
        {
            oid = GetOID(pMsg, item.nSize);

            switch (oid)
            {
            case OID_HASH_MD2_RSA:
                pCert->hashAlgorithm = HASH_MD2_WITH_RSA;
                break;
            case OID_HASH_MD4_RSA:
                pCert->hashAlgorithm = HASH_MD4_WITH_RSA;
                break;
            case OID_HASH_MD5_RSA:
                pCert->hashAlgorithm = HASH_MD5_WITH_RSA;
                break;
            case OID_HASH_SHA1_RSA:
                pCert->hashAlgorithm = HASH_SHA1_WITH_RSA;
                break;
            case OID_HASH_SHA256_RSA:
                pCert->hashAlgorithm = HASH_SHA256_WITH_RSA;
                break;
            default:
                break;
            }
        }
        pMsg += item.nSize;
        nParsed += item.nSize;

        // This should be a NULL tag
        nHeadSize = GetASN1Item(&item, pMsg);

        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        pMsg += item.nSize;
        nParsed += item.nSize;
    }
    else
    {
        //Bail out on any suspected data corruption.
        return 0;
    }

    // 3. A sequence containing the Issuer identity information
    nHeadSize = GetASN1Item(&item, pMsg);
    nParseSize = ParseX509ID(&(pCert->issuer), pMsg, (item.nSize+nHeadSize));
    //assert(nParseSize == (item.nSize+nHeadSize));
    pMsg += nParseSize;
    nParsed += nParseSize;

    // 4. A sequence containing the begin and end validity date.
    nHeadSize = GetASN1Item(&item, pMsg);
    pMsg    += nHeadSize;
    nParsed += nHeadSize;

    if (item.nType == SEQUENCE_TAG)
    {
        // First the certificate activation datetime.
        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if (item.nType == UTCTIME_TAG)
        {
            nParseSize = ParseUTCTime(&(pCert->enableTime), pMsg, item.nSize);
        }
        else if (item.nType == GENTIME_TAG)
        {
            nParseSize = ParseGENTime(&(pCert->enableTime), pMsg, item.nSize);
        }
        else
        {
            nParseSize = item.nSize;
        }

        pMsg    += nParseSize;
        nParsed += nParseSize;

        // Then the certificate expiration datetime.
        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if (item.nType == UTCTIME_TAG)
        {
            nParseSize = ParseUTCTime(&(pCert->expireTime), pMsg, item.nSize);
        }
        else if (item.nType == GENTIME_TAG)
        {
            nParseSize = ParseGENTime(&(pCert->expireTime), pMsg, item.nSize);
        }
        else
        {
            nParseSize = item.nSize;
        }

        if (nParseSize != item.nSize)
        {
            //Bail out on any suspected data corruption.
            return 0;
        }

        pMsg    += nParseSize;
        nParsed += nParseSize;
    }
    else
    {
        pMsg += item.nSize;
        nParsed += item.nSize;

        //Bail out on any suspected data corruption.
        return 0;
    }


    // 5. A sequence containing the Subject identity information
    nHeadSize = GetASN1Item(&item, pMsg);
    nParseSize = ParseX509ID(&(pCert->name), pMsg, (item.nSize+nHeadSize));
    //assert(nParseSize == (item.nSize+nHeadSize));
    pMsg += nParseSize;
    nParsed += nParseSize;

    // 6. A sequence containing the public key information
    nHeadSize = GetASN1Item(&item, pMsg);
    pMsg    += nHeadSize;
    nParsed += nHeadSize;

    if (item.nType == SEQUENCE_TAG)
    {
        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if (item.nType == SEQUENCE_TAG)
        {
            OID     oid = OID_UNKNOWN;
            nHeadSize = GetASN1Item(&item, pMsg);
            pMsg    += nHeadSize;
            nParsed += nHeadSize;

            if (item.nType == OID_TAG)
            {
                oid = GetOID(pMsg, item.nSize);
            }

            pMsg += item.nSize;
            nParsed += item.nSize;

            nHeadSize = GetASN1Item(&item, pMsg);
            pMsg    += nHeadSize;
            nParsed += nHeadSize;

            pMsg += item.nSize;
            nParsed += item.nSize;
        }
        else
        {
            pMsg += item.nSize;
            nParsed += item.nSize;
        }

        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if (item.nType == BITSTRING_TAG)
        {
            nHeadSize = GetASN1Item(&item, pMsg);
            pMsg    += nHeadSize;
            nParsed += nHeadSize;

            if (item.nType == SEQUENCE_TAG)
            {
                // First an Integer which is the public key
                nHeadSize = GetASN1Item(&item, pMsg);
                pMsg    += nHeadSize;
                nParsed += nHeadSize;

                if (item.nType == INTEGER_TAG)
                {
                    if (0 == (item.nSize & 0x00000001))
                    {
                        // OK. We have exactly even bytes.
                    }
                    else if (0x00 == (*pMsg))
                    {
                        // We have odd bytes, but 1st byte is 0. Discard it.
                        pMsg++;
                        nParsed++;
                        item.nSize --;
                    }
                    else
                    {
                        //assert(0);  //We may be in trouble.
                    }
                    
                    if (item.nSize <= sizeof(pCert->pubKey))
                    {
                        memset(&(pCert->pubKey), 0, sizeof(pCert->pubKey));
                        memcpy(
                            &(pCert->pubKey[sizeof(pCert->pubKey) - item.nSize]),
                            pMsg,
                            item.nSize
                            );
                        pCert->pubKeyLen = item.nSize;
                    }
                }
                pMsg    += item.nSize;
                nParsed += item.nSize;

                // Then an Integer which is the public exponent
                nHeadSize = GetASN1Item(&item, pMsg);
                pMsg    += nHeadSize;
                nParsed += nHeadSize;

                if (item.nType == INTEGER_TAG)
                {
                    uint    i;

                    pCert->pubExp = 0;
                    for (i=0; i<item.nSize; i++)
                    {
                        pCert->pubExp <<= 8;
                        pCert->pubExp += *pMsg++;
                        nParsed ++;
                    }
                }
                else
                {
                    pMsg    += item.nSize;
                    nParsed += item.nSize;
                }
            }
            else
            {
                pMsg += item.nSize;
                nParsed += item.nSize;
            }
        }
        else
        {
            pMsg += item.nSize;
            nParsed += item.nSize;
        }
    }
    else
    {
        pMsg += item.nSize;
        nParsed += item.nSize;

        //Bail out on any suspected data corruption.
        return 0;
    }


    //There may be additional fields
    while (nParsed < nMsgSize)
    {
        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        //assert((item.nType & (CLASS_MASK|FORM_MASK)) == (CLASS_CONTEXT|FORM_CONSTRUCTED));
        //If we are interested in the additional fields, maining the constructed
        //field [1], [2], [3], parse it here.

        pMsg += item.nSize;
        nParsed += item.nSize;
    }

    //assert (nParsed == nMsgSize);
    if (nParsed != nMsgSize)
    {
        //Bail out on any suspected data corruption.
        return 0;
    }

    return nParsed;
}


/******************************************************************************
* Function:     ParseX509ID
*
* Description:  Parse the X.509 identity information. This largely replaces
*               the old ParseX509Name() function.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseX509ID
(
    X509NAME*       pName,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uint        nParsed = 0, nParseSize = 0;
    uint        nHeadSize;
    ASN1ITEM    item;
    MD5         md5Ctx;
    const CIPHER* pMd5 = &(gpCipherSet->md5);

    pMd5->Init(&md5Ctx, pMd5->pIData);
    memset(pName, 0, sizeof(*pName));

    while (nParsed < nMsgSize)
    {

        // 3. A sequence containing the Issuer identity information
        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if (item.nType != SEQUENCE_TAG)
        {
            pMsg += item.nSize;
            nParsed += item.nSize;

            continue;
        }

        //X.509 identity parsing. First hash everyting as a unique identifier.
        pMd5->Hash(pMsg, item.nSize, pName->md5digest);

        while (nParsed < nMsgSize)
        {
            OID     oid = OID_UNKNOWN;

            nHeadSize = GetASN1Item(&item, pMsg);
            pMsg    += nHeadSize;
            nParsed += nHeadSize;

            if (item.nType != SET_TAG)
            {
                pMsg += item.nSize;
                nParsed += item.nSize;
                continue;
            }

            nHeadSize = GetASN1Item(&item, pMsg);
            pMsg    += nHeadSize;
            nParsed += nHeadSize;

            if (item.nType != SEQUENCE_TAG)
            {
                pMsg += item.nSize;
                nParsed += item.nSize;
                continue;
            }

            //Each Sequence within the SET is one OID followed by one PrintableString.

            //First the OID tag.
            nHeadSize = GetASN1Item(&item, pMsg);
            pMsg    += nHeadSize;
            nParsed += nHeadSize;

            if (item.nType == OID_TAG)
            {
                oid = GetOID(pMsg, item.nSize);
            }
            pMsg    += item.nSize;
            nParsed += item.nSize;

            //Then the PrintableString.
            nHeadSize = GetASN1Item(&item, pMsg);
            pMsg    += nHeadSize;
            nParsed += nHeadSize;

            if ((item.nType == PRINTABLE_STRING_TAG) ||
                (item.nType == TAG_IA5STRING) ||
                (item.nType == TAG_T61STRING) )
            {
                uint    nSize = item.nSize;
                char    tmpStr[sizeof(pName->CommonName)];

                if (nSize > (sizeof(tmpStr)-1))
                {
                    nSize = sizeof(tmpStr)-1;
                }
                memcpy(tmpStr, pMsg, nSize);
                memset(tmpStr+nSize, 0, sizeof(tmpStr)-nSize);

                switch (oid)
                {
                case OID_NAME_COMMON:
                    memcpy(pName->CommonName, tmpStr, sizeof(pName->CommonName));
                    break;
                case OID_NAME_ORG:
                    pMd5->Input(&md5Ctx, pMsg, item.nSize);
                    memcpy(pName->orgName, tmpStr, sizeof(pName->orgName));
                    break;
                case OID_NAME_UNIT:
                    pMd5->Input(&md5Ctx, pMsg, item.nSize);
                    memcpy(pName->orgUnit, tmpStr, sizeof(pName->orgUnit));
                    //Just in case there is no common name.
                    //memcpy(pName->CommonName, tmpStr, sizeof(pName->CommonName));
                    break;
                case OID_NAME_LOCAL:
                    pMd5->Input(&md5Ctx, pMsg, item.nSize);
                    memcpy(pName->localName, tmpStr, sizeof(pName->localName));
                    break;
                case OID_NAME_STATE:
                    memcpy(pName->state, tmpStr, sizeof(pName->state));
                    break;
                case OID_NAME_COUNTRY:
                    memcpy(pName->country, tmpStr, sizeof(pName->country));
                    break;
                case OID_EMAIL2:
                    tmpStr[0] |= 0x80;
                    //Fall through
                case OID_EMAIL:
                    memcpy(pName->emailaddress, tmpStr, sizeof(pName->emailaddress));
                    break;
                default:
                    pMsg = pMsg;
                    break;
                }
            }
            pMsg    += item.nSize;
            nParsed += item.nSize;
        }
    }

    pMd5->Digest(&md5Ctx, pName->md5digest2);

    // We should have parsed exactly all the bytes.
    if (nParsed != nMsgSize)
    {
        //Bail out on any suspected data corruption.
        return 0;
    }

    return nParsed;
}


/******************************************************************************
* Function:     ParseX509Name
*
* Description:  Parse the NAME portion of the TBSCertificate. Normally there
*               are two NAME's, first is the issuer NAME, second is the subject
*               (certificate holder) NAME. The information is put into the
*               X509NAME struct. Since what's contained in a NAME varies. We
*               used a MD5 hash of the whole NAME section (minus the SEQUENCE
*               tag that wraps it) to uniquely identify a NAME and determine
*               if a NAME matches.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint ParseX509Name
(
    X509NAME*       pName,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    uint        nParsed = 0;
    uint        nHeadSize;
    ASN1ITEM    item;

    gpCipherSet->md5.Hash(pMsg, nMsgSize, pName->md5digest);

    while (nParsed < nMsgSize)
    {
        OID     oid = OID_UNKNOWN;

        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if (item.nType != SET_TAG)
        {
            pMsg += item.nSize;
            nParsed += item.nSize;
            continue;
        }

        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if (item.nType != SEQUENCE_TAG)
        {
            pMsg += item.nSize;
            nParsed += item.nSize;
            continue;
        }

        //Each Sequence within the SET is one OID followed by one PrintableString.

        //First the OID tag.
        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if (item.nType == OID_TAG)
        {
            oid = GetOID(pMsg, item.nSize);
        }
        pMsg    += item.nSize;
        nParsed += item.nSize;

        //Then the PrintableString.
        nHeadSize = GetASN1Item(&item, pMsg);
        pMsg    += nHeadSize;
        nParsed += nHeadSize;

        if ((item.nType == PRINTABLE_STRING_TAG) ||
            (item.nType == TAG_IA5STRING) ||
            (item.nType == TAG_T61STRING) )
        {
            uint    nSize = item.nSize;
            char    tmpStr[sizeof(pName->CommonName)];

            if (nSize > (sizeof(tmpStr)-1))
            {
                nSize = sizeof(tmpStr)-1;
            }
            memcpy(tmpStr, pMsg, nSize);
            tmpStr[nSize] = 0x00;

            //Currently we record only the commonName and ignore all else.
            switch (oid)
            {
            case OID_NAME_COMMON:
                memcpy(pName->CommonName, tmpStr, sizeof(pName->CommonName));
                break;
            case OID_NAME_ORG:
                break;
            case OID_NAME_UNIT:
                //Just in case there is no common name.
                memcpy(pName->CommonName, tmpStr, sizeof(pName->CommonName));
                break;
            case OID_NAME_LOCAL:
                break;
            case OID_NAME_STATE:
                break;
            case OID_NAME_COUNTRY:
                break;
            default:
                break;
            }
        }
        pMsg    += item.nSize;
        nParsed += item.nSize;
    }

    //assert(nParsed == nMsgSize);   // We should have parsed exactly all the bytes.
    return nParsed;
}


/******************************************************************************
* Function:     ParseUTCTime
*
* Description:  Parse the UTC Time string and return the date time in Julian
*               seconds.
*
* Returns:      The number of bytes parsed.
******************************************************************************/
uint ParseUTCTime
(
    DATETIME*       pTime,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    int     year;
    int     month;
    int     day;
    int     hour;
    int     minute;
    int     second;

    sscanf((char*)pMsg, "%02d%02d%02d%02d%02d%02d",
        &year, &month, &day, &hour, &minute, &second);

    // This calculation is good for year 00-99 (2000-2099).
    pTime->day = 367*year;
    pTime->day -= (((year+((month+9)/12))*7)/4);
    pTime->day += (month*275)/9;
    pTime->day += day + 2451513;

    if (year >= 70)
    {
        //the year is 1970-1999, not 2070 to 2099! So adjust by 36525 days,
        //Which is the exact difference between same date 19XX and 20XX.
        pTime->day -= 36525;
    }

    if (hour >= 12)
    {
        pTime->day ++;
        hour -= 12;
    }
    else
    {
        hour += 12;
    }

    pTime->second = (((hour*60)+minute)*60)+second;
    
    return nMsgSize;
}


/******************************************************************************
* Function:     ParseGENTime
*
* Description:  Parse the Generalized Time string and return the date time in
*               Julian day and seconds. NOTE: I do not know what is the
*               difference between UTCTime and GeneralizedTime. For now
*               treat them the same.
*
* Returns:      The number of bytes parsed.
******************************************************************************/
uint ParseGENTime
(
    DATETIME*       pTime,
    const uchar*    pMsg,
    uint            nMsgSize
)
{
    int     year;
    int     month;
    int     day;
    int     hour;
    int     minute;
    int     second;

    if (nMsgSize >= 15)
    {
        //The year is 4 digits, not two, ignore the first two digits.
        pMsg += 2;
    }
    sscanf((char*)pMsg, "%02d%02d%02d%02d%02d%02d",
        &year, &month, &day, &hour, &minute, &second);
    if (pMsg[12] == '+' || pMsg[12] == '-')
    {
        //Time zone adjustment
        char    c;
        int     nAdjust = 0;
        sscanf((char*)&(pMsg[12]), "%c%02d", &c, &nAdjust);

        if (c == '+')
        {
            hour -= nAdjust;
        }
        else if (c == '-')
        {
            hour += nAdjust;
        }
        else
        {
            //No time zone adjustment.
        }

        if (hour >= 24)
        {
            day ++;
            hour -= 24;
        }

        if (hour < 0)
        {
            day --;
            hour += 24;
        }
    }

    // This calculation is good for year 00-99 (2000-2099).
    pTime->day = 367*year;
    pTime->day -= (((year+((month+9)/12))*7)/4);
    pTime->day += (month*275)/9;
    pTime->day += day + 2451513;

    if (year >= 90)
    {
        //the year is 1990-1999, not 2070 to 2099! So adjust by 36525 days,
        //Which is the exact difference between same date 19XX and 20XX.
        pTime->day -= 36525;
    }

    if (hour >= 12)
    {
        pTime->day ++;
        hour -= 12;
    }
    else
    {
        hour += 12;
    }

    pTime->second = (((hour*60)+minute)*60)+second;
    
    return nMsgSize;
}


/******************************************************************************
* Function:     VerifySignature
*
* Description:  Verify if signature contained in one certificate is signed by
*               the holder of another certificate. This can also be used to
*               verify a self-signing signature.
*
* Returns:      Zero if all verify OK. Else a none-zero return.
******************************************************************************/
uint VerifySignature
(
    const CERT* pCert,
    const CERT* pSigner
)
{
    uint    nDigestSize = sizeof(pCert->signature);
    uchar   signature[sizeof(pCert->signature)];

    //First, is the issuer certificate the correct one to use?
    if (NotSameX509Name(&(pCert->issuer), &(pSigner->name)))
    {
        return SIGNATURE_WRONG_CERTIFICATE;
    }

    if ((0 == pSigner->pubKeyLen) || (0x00 == (0x01 & pSigner->pubKey[sizeof(pSigner->pubKey)-1])))
    {
        return SIGNATURE_WRONG_CERTIFICATE;
    }

    memcpy(signature, pCert->signature, sizeof(signature));
    BN_Encrypt(
        &(signature[sizeof(signature) - pSigner->pubKeyLen]),
        &(pSigner->pubKey[sizeof(pSigner->pubKey)-pSigner->pubKeyLen]),
        pSigner->pubExp,
        pSigner->pubKeyLen
        );

    switch(pCert->hashAlgorithm)
    {
    case HASH_MD2_WITH_RSA:
        //assert(oid == OID_DIGEST_MD2);  //Test
        nDigestSize = 0;
        break;
    case HASH_MD4_WITH_RSA:
        //assert(oid == OID_DIGEST_MD4);  //Test
        nDigestSize = 0;
        break;
    case HASH_MD5_WITH_RSA:
        //assert(oid == OID_DIGEST_MD5);  //Test
        nDigestSize = MD5_SIZE;
        break;
    case HASH_SHA1_WITH_RSA:
        //assert(oid == OID_DIGEST_SHA1);  //Test
        nDigestSize = SHA1_SIZE;
        break;
    case HASH_SHA256_WITH_RSA:
        //assert(oid == OID_DIGEST_SHA1);  //Test
        nDigestSize = SHA256_SIZE;
        break;
    default:
        break;
    }

    if (0 == memcmp(
        &(pCert->digest[sizeof(pCert->digest) - nDigestSize]),
        &(signature[sizeof(signature)-nDigestSize]),
        nDigestSize
        ) )
    {
        return SIGNATURE_OK;
    }
    else
    {
        return SIGNATURE_INVALID;
    }
}


/******************************************************************************
* Function:     GetPubKeyLen
*
* Description:  Obtain the length of the public key of the certificate. This
*               is length of the certificate holder's public key, not the
*               certificate signer's public key.
*
* Returns:      Public Key length in bytes, not bits.
******************************************************************************/
uint GetPubKeyLen
(
    const CERT* pCert
)
{
    return pCert->pubKeyLen;
}


/******************************************************************************
* Function:     EncryptByCert
*
* Description:  Encrypt using the public key contained in the certificate.
*               The size of data to be encrypted must match the length of
*               the public key. Note only public key is needed to do RSA
*               encryption but private key is needed to do decryption.
*
* Returns:      Bytes encrypted, if encrypted. Else zero.
******************************************************************************/
uint EncryptByCert
(
    const CERT* pCert,
    uchar*      pData,
    uint        nDataSize
)
{
    if (nDataSize != pCert->pubKeyLen) {return 0;}

    BN_Encrypt(
        pData,
        &(pCert->pubKey[sizeof(pCert->pubKey) - pCert->pubKeyLen]),
        pCert->pubExp,
        pCert->pubKeyLen
        );

    return nDataSize;
}


/******************************************************************************
* Function:     AuthenticateCert
*
* Description:  Attempt to authenticate a certificate. Note we are returning
*               more information than simply a Yes or NO.
*
* Returns:      The status of the certificate, to be interpretted based on
*               the bit combination of the status.
******************************************************************************/
CERT_STATUS AuthenticateCert
(
    CERT*     pCert,
    CERT**    ppMidCerts
)
{
    CERT_STATUS         eStatus;
    CERT*     pCert2;

    if (NULL == pCert) {return CS_NONE_EXIST;}

    if (pCert->status & CS_VERIFIED)
    {
        return pCert->status;
    }

    if (ppMidCerts == NULL)
    {
        ppMidCerts = &gpMidCerts;
    }

    //We only check expiration time if we know the time.
    if (0 != pCert->receiveTime)
    {
        //Has the certificate expired?
        DATETIME        curTime;

        //The UnixTime in seconds is counted from 1970 01/01 00:00am UTC,
        //which in Julian date is 2440587.5. See US Navy Site:
        //  http://aa.usno.navy.mil/data/docs/JulianDate.html
        curTime.day    = pCert->receiveTime/86400;
        curTime.second = pCert->receiveTime - (curTime.day*86400) + 43200;
        curTime.day   += 2440587;
        if (curTime.second >= 86400)
        {
            curTime.day ++;
            curTime.second -= 86400;
        }

        if (curTime.day < pCert->expireTime.day)
        {
            //We are OK.
        }
        else if ((curTime.day > pCert->expireTime.day) ||
            (curTime.second >= pCert->expireTime.second) )
        {
            //The certificate expired.
            pCert->status |= CS_EXPIRED;
        }
    }

    if (NULL == pCert->pRootCert)
    {
        if (0 == NotSameX509Name(&(pCert->name), &(pCert->issuer)))
        {
            pCert->status |= CS_SELF;
            pCert2 = pCert;
        }
        else
        {
            pCert->status &= ~CS_SELF;
            pCert2 = FindCert(&(pCert->issuer), ppMidCerts);
        }

        pCert->pRootCert = pCert2;

        if ((NULL != pCert2) && (0 == VerifySignature(pCert, pCert2)))
        {
            if (pCert->status & CS_SELF)
            {
                pCert->status &= ~CS_PENDING;
                pCert->status |= CS_VERIFIED;
                if (pCert->status & CS_ROOT)
                {
                    pCert->status |= CS_OK;
                }
            }
            else
            {
                pCert->status |= CS_PENDING;
            }
        }
        else
        {
            pCert->status &= ~CS_PENDING;
            pCert->status |= CS_BAD;
            pCert->status |= CS_VERIFIED;
        }
    }

    if ((pCert->status & CS_PENDING) != CS_PENDING)
    {
        return pCert->status;
    }

    if (pCert->status & CS_SELF)
    {
        return pCert->status;
    }
    else
    {
        eStatus = AuthenticateCert(pCert->pRootCert, ppMidCerts);

        if ((eStatus & CS_PENDING) != CS_PENDING)
        {
            pCert->status &= ~CS_PENDING;
            pCert->status |= eStatus & (CS_PENDING | CS_EXPIRED);
            pCert->status |= CS_VERIFIED;
        }
    }

    return pCert->status;
}


/******************************************************************************
* Function:     GetPubKey
*
* Description:  Returns the public key contained in the certificate, in the
*               big endian convention, same as in the certificate.
*
* Returns:      Size of the public key in bytes. Or zero if no key found.
******************************************************************************/
uint GetPubKey
(
    const CERT* pCert,
    uchar*      pKey
)
{
    if (NULL != pKey)
    {
        memcpy(pKey, &(pCert->pubKey[sizeof(pCert->pubKey) - pCert->pubKeyLen]), pCert->pubKeyLen);

        return pCert->pubKeyLen;
    }

    return 0;
}


/******************************************************************************
* Function:     GetPubExp
*
* Description:  Returns the public key exponent contained in the certificate,
*               which is mostly a small integer. Most likely 17 or 65537.
*
* Returns:      Integer representing the public exponent.
******************************************************************************/
uint GetPubExp
(
    const CERT* pCert
)
{
    return pCert->pubExp;
}


/******************************************************************************
* Function:     GetCertName
*
* Description:  Get the common name of the certificate already parsed.
*
* Returns:      A const pointer to the null terminated common name string.
******************************************************************************/
const char* GetCertName
(
    const struct CERT* pCert
)
{
    return pCert->name.CommonName;
}


/******************************************************************************
* Function:     GetUniqueName
*
* Description:  Extract the distinguished name block by parsing the message
*               normally what's being parsed is part of a certificate and we
*               want to extract the certificate holder's name. But by intentionally
*               negate the nMsgSize to negative, we may parse a unique name block and
*               the pCert pointer is actually a pointer to struct X509NAME.
*
* Returns:      Number of bytes parsed.
******************************************************************************/
uint GetUniqueName
(
    const CERT* pCert,
    uchar*      pMsgBuff,
    uint        nMsgSize
)
{
#define SET_COUNT       7   //Magic number, do not change.
#define SET_OVERHEAD    11  //Magic number, do not change.
#define SET_OVERHEAD2   17  //Magic number, do not change.

    uint            i, nLen = 0, nMagic;
    OID             oid;
    uchar*  pMsg =  pMsgBuff;
    const X509NAME* pName = &(pCert->name);
    uint            nSizes[SET_COUNT];

    //Do a little bit magic here
    if (((int)nMsgSize) < 0)
    {
        //What we passed in is X509NAME pointer, not cert pointer
        pName = (const X509NAME*)pCert;
        nMsgSize = 0 - nMsgSize;
    }

    memset(&nSizes, 0, sizeof(nSizes));

    //First calculate the total message length
    //The message is composed of 1 to 6 sets, each set is 11 bytes plus
    //the length of the string. Do not change the following order!
    if ((nSizes[0] = strlen(pName->country)) > 0) {nLen += nSizes[0] + SET_OVERHEAD;}
    if ((nSizes[1] = strlen(pName->state  )) > 0) {nLen += nSizes[1] + SET_OVERHEAD;}
    if ((nSizes[2] = strlen(pName->localName))>0) {nLen += nSizes[2] + SET_OVERHEAD;}
    if ((nSizes[3] = strlen(pName->orgName)) > 0) {nLen += nSizes[3] + SET_OVERHEAD;}
    if ((nSizes[4] = strlen(pName->orgUnit)) > 0) {nLen += nSizes[4] + SET_OVERHEAD;}
    if ((nSizes[5] = strlen(pName->CommonName))>0){nLen += nSizes[5] + SET_OVERHEAD;}
    if ((nSizes[6] = strlen(pName->emailaddress))>0){nLen += nSizes[6] + SET_OVERHEAD2;}

    //OK we can start to construct the message
    *pMsg++ = SEQUENCE_TAG;
    if (nLen >= 0x0100)
    {
    *pMsg++ = 0x82;
    *pMsg++ = (uchar)(nLen>>8);
    }
    else if (nLen >= 0x0080)
    {
    *pMsg++ = 0x81;
    }
    *pMsg++ = (uchar)(nLen>>0);

    for (i=0; i<SET_COUNT; i++)
    {
        const char* pString = NULL;

        //Set 1: Country
        if ((nMagic = nSizes[i]) == 0) continue;

        switch (i)
        {
        case 0: oid = OID_NAME_COUNTRY;
                pString = pName->country;
                break;
        case 1: oid = OID_NAME_STATE;
                pString = pName->state;
                break;
        case 2: oid = OID_NAME_LOCAL;
                pString = pName->localName;
                break;
        case 3: oid = OID_NAME_ORG;
                pString = pName->orgName;
                break;
        case 4: oid = OID_NAME_UNIT;
                pString = pName->orgUnit;
                break;
        case 5: oid = OID_NAME_COMMON;
                pString = pName->CommonName;
                break;
        case 6: oid = OID_EMAIL;
                if (pName->emailaddress[0] & 0x80)
                {
                    nMagic ++;
                    oid = OID_EMAIL2;
                }
                pString = pName->emailaddress;
                nMagic += SET_OVERHEAD2-SET_OVERHEAD;
                break;
        default:
            oid = OID_UNKNOWN;
            break;
        }

        nMagic += SET_OVERHEAD - 2;
        *pMsg++ = SET_TAG;
        *pMsg++ = (uchar)(nMagic>>0);

        nMagic -= 2;
        *pMsg++ = SEQUENCE_TAG;
        *pMsg++ = (uchar)(nMagic>>0);

        nMagic -= 2;
        *pMsg++ = OID_TAG;
        *pMsg++ = (uchar)(0x03);

        nMagic -= 2;
        pMsg[-1] = SetOID(pMsg, oid);
        nMagic -= pMsg[-1];
        pMsg += pMsg[-1];

        *pMsg++ = (oid == OID_EMAIL)?IA5STRING_TAG:PRINTABLE_STRING_TAG;
        *pMsg++ = (uchar)(nMagic>>0);

        memcpy(pMsg, pString, nMagic);

        if (oid == OID_EMAIL2)
        {
            pMsg[0] &= 0x7F;
        }
        pMsg += nMagic;
    }

    return (pMsg - pMsgBuff);
}


#ifdef CERT_TEST

#include <malloc.h>

#include "certSamples.h"

uint DoCertTest()
{
    uint        len = 0, size=0, ret = 0;
    CERT*       pRoot = NULL;
    CERT*       pCert = NULL;
    CERT_STATUS eStatus = CS_UNKNOWN;
    const CIPHERSET* pMyCiphers = NULL;

    pMyCiphers = InitCiphers(&gCipherSet, NULL);

    StartCerts(malloc, free, pMyCiphers);
    pRoot = CreateCert(CS_ROOT, 0);
    len = ParseCert(pRoot, gGeoTrustRoot, sizeof(gGeoTrustRoot));
    ret |= len - sizeof(gGeoTrustRoot);
    eStatus = AuthenticateCert(pRoot, NULL);
    ret |= eStatus ^ (CS_ROOT|CS_SELF|CS_OK|CS_VERIFIED);
    InsertCert(pRoot, NULL);

    pCert = CreateCert(CS_UNKNOWN, 0);
    len = ParseCert(pCert, gGoogleCA, sizeof(gGoogleCA));
    ret |= len - sizeof(gGoogleCA);
    eStatus = AuthenticateCert(pCert, NULL);
    ret |= eStatus ^ (CS_OK|CS_VERIFIED);
    InsertCert(pCert, NULL);

    CleanupCerts(NULL);

    return ret;
}

#endif //CERT_TEST
