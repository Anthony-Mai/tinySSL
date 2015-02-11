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
*  File Name:       md5.c
*
*  Description:     MD5 hash algorithm implementation. MD5 is no longer safe.
*                   It is recommended NOT to be used. Included for completeness.
*
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         6/27/2014 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <string.h>
#include <stdint.h>

#include "cipher.h"

#define MD5     CTX
#define DSIZE   MD5_SIZE

#include "md5.h"
#include "endian.h"

// Constants for Md5Round routine.

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21


// F, G, H and I are basic MD5 functions.
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

// ROTATE_LEFT rotates x left n bits.
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.
#define FF(a, b, c, d, x, s, ac) {(a)+=F((b),(c),(d))+(x)+(ac); (a)=ROTATE_LEFT((a),(s)); (a)+=(b);}
#define GG(a, b, c, d, x, s, ac) {(a)+=G((b),(c),(d))+(x)+(ac); (a)=ROTATE_LEFT((a),(s)); (a)+=(b);}
#define HH(a, b, c, d, x, s, ac) {(a)+=H((b),(c),(d))+(x)+(ac); (a)=ROTATE_LEFT((a),(s)); (a)+=(b);}
#define II(a, b, c, d, x, s, ac) {(a)+=I((b),(c),(d))+(x)+(ac); (a)=ROTATE_LEFT((a),(s)); (a)+=(b);}


typedef struct CDAT
{
    uint    state[4];
    uint    Lo,Hi;
} CDAT;

const CDAT* Md5Cd()
{
    static const CDAT  cMd5Cd = {
        {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476},
        0, 0
    };

    return &cMd5Cd;
}


/******************************************************************************
* Function:     SetMd5
*
* Description:  Set the MD5 cipher
*
* Returns:      None.
******************************************************************************/
void SetMd5(CIPHER* pCipher)
{
    pCipher->eCipher = CIPHER_MD5;
    pCipher->cSize = sizeof(CTX);
    pCipher->dSize = DSIZE;
    pCipher->pIData = Md5Cd();

    pCipher->Init  = Md5Init;
    pCipher->Input = Md5Input;
    pCipher->Digest= Md5Digest;
    pCipher->Hash  = Md5Hash;
}


/******************************************************************************
* Function:     Md5Round
*
* Description:  MD5 basic transformation. Transforms state based on block.
*
* Returns:      None
******************************************************************************/
void Md5Round
(
    MD5*    pMD5
)
{
    uint   a=pMD5->state[0], b=pMD5->state[1], c=pMD5->state[2], d=pMD5->state[3];
    uint*  x = pMD5->ints;

    // Round 1
    FF(a, b, c, d, x[0],  S11, 0xD76AA478); // 1
    FF(d, a, b, c, x[1],  S12, 0xE8C7B756); // 2
    FF(c, d, a, b, x[2],  S13, 0x242070DB); // 3
    FF(b, c, d, a, x[3],  S14, 0xC1BDCEEE); // 4
    FF(a, b, c, d, x[4],  S11, 0xF57C0FAF); // 5
    FF(d, a, b, c, x[5],  S12, 0x4787C62A); // 6
    FF(c, d, a, b, x[6],  S13, 0xA8304613); // 7
    FF(b, c, d, a, x[7],  S14, 0xFD469501); // 8
    FF(a, b, c, d, x[8],  S11, 0x698098D8); // 9
    FF(d, a, b, c, x[9],  S12, 0x8B44F7AF); // 10
    FF(c, d, a, b, x[10], S13, 0xFFFF5BB1); // 11
    FF(b, c, d, a, x[11], S14, 0x895CD7BE); // 12
    FF(a, b, c, d, x[12], S11, 0x6B901122); // 13
    FF(d, a, b, c, x[13], S12, 0xFD987193); // 14
    FF(c, d, a, b, x[14], S13, 0xA679438E); // 15
    FF(b, c, d, a, x[15], S14, 0x49B40821); // 16

    // Round 2
    GG(a, b, c, d, x[1],  S21, 0xF61E2562); // 17
    GG(d, a, b, c, x[6],  S22, 0xC040B340); // 18
    GG(c, d, a, b, x[11], S23, 0x265E5A51); // 19
    GG(b, c, d, a, x[0],  S24, 0xE9B6C7AA); // 20
    GG(a, b, c, d, x[5],  S21, 0xD62F105D); // 21
    GG(d, a, b, c, x[10], S22, 0x02441453); // 22
    GG(c, d, a, b, x[15], S23, 0xD8A1E681); // 23
    GG(b, c, d, a, x[4],  S24, 0xE7D3FBC8); // 24
    GG(a, b, c, d, x[9],  S21, 0x21E1CDE6); // 25
    GG(d, a, b, c, x[14], S22, 0xC33707D6); // 26
    GG(c, d, a, b, x[3],  S23, 0xF4D50D87); // 27
    GG(b, c, d, a, x[8],  S24, 0x455A14ED); // 28
    GG(a, b, c, d, x[13], S21, 0xA9E3E905); // 29
    GG(d, a, b, c, x[2],  S22, 0xFCEFA3F8); // 30
    GG(c, d, a, b, x[7],  S23, 0x676F02D9); // 31
    GG(b, c, d, a, x[12], S24, 0x8D2A4C8A); // 32

    // Round 3
    HH(a, b, c, d, x[5],  S31, 0xFFFA3942); // 33
    HH(d, a, b, c, x[8],  S32, 0x8771F681); // 34
    HH(c, d, a, b, x[11], S33, 0x6D9D6122); // 35
    HH(b, c, d, a, x[14], S34, 0xFDE5380C); // 36
    HH(a, b, c, d, x[1],  S31, 0xA4BEEA44); // 37
    HH(d, a, b, c, x[4],  S32, 0x4BDECFA9); // 38
    HH(c, d, a, b, x[7],  S33, 0xF6BB4B60); // 39
    HH(b, c, d, a, x[10], S34, 0xBEBFBC70); // 40
    HH(a, b, c, d, x[13], S31, 0x289B7EC6); // 41
    HH(d, a, b, c, x[0],  S32, 0xEAA127FA); // 42
    HH(c, d, a, b, x[3],  S33, 0xD4EF3085); // 43
    HH(b, c, d, a, x[6],  S34, 0x04881D05); // 44
    HH(a, b, c, d, x[9],  S31, 0xD9D4D039); // 45
    HH(d, a, b, c, x[12], S32, 0xE6DB99E5); // 46
    HH(c, d, a, b, x[15], S33, 0x1FA27CF8); // 47
    HH(b, c, d, a, x[2],  S34, 0xC4AC5665); // 48

    // Round 4
    II(a, b, c, d, x[0],  S41, 0xF4292244); // 49
    II(d, a, b, c, x[7],  S42, 0x432AFF97); // 50
    II(c, d, a, b, x[14], S43, 0xAB9423A7); // 51
    II(b, c, d, a, x[5],  S44, 0xFC93A039); // 52
    II(a, b, c, d, x[12], S41, 0x655B59C3); // 53
    II(d, a, b, c, x[3],  S42, 0x8F0CCC92); // 54
    II(c, d, a, b, x[10], S43, 0xFFEFF47D); // 55
    II(b, c, d, a, x[1],  S44, 0x85845DD1); // 56
    II(a, b, c, d, x[8],  S41, 0x6FA87E4F); // 57
    II(d, a, b, c, x[15], S42, 0xFE2CE6E0); // 58
    II(c, d, a, b, x[6],  S43, 0xA3014314); // 59
    II(b, c, d, a, x[13], S44, 0x4E0811A1); // 60
    II(a, b, c, d, x[4],  S41, 0xF7537E82); // 61
    II(d, a, b, c, x[11], S42, 0xBD3AF235); // 62
    II(c, d, a, b, x[2],  S43, 0x2AD7D2BB); // 63
    II(b, c, d, a, x[9],  S44, 0xEB86D391); // 64

    pMD5->state[0]+=a; pMD5->state[1]+=b; pMD5->state[2]+=c; pMD5->state[3]+=d;
}


/******************************************************************************
* Function:     Md5Init
*
* Description:  MD5 initialization. Begins an MD5 operation, writing a new pMd5.
*
* Returns:      None.
******************************************************************************/
void Md5Init
(
    MD5*        pMd5,   //MD5 context
    const CDAT* pIData  //MD5 init data
)
{
    if (pIData == NULL) pIData = Md5Cd();

    pMd5->countLo = pIData->Lo;
    pMd5->countHi = pIData->Hi;

    // Load magic initialization constants.
    pMd5->state[0] = pIData->state[0];
    pMd5->state[1] = pIData->state[1];
    pMd5->state[2] = pIData->state[2];
    pMd5->state[3] = pIData->state[3];

//    pMd5->state[0] = 0X67452301;
//    pMd5->state[1] = 0XEFCDAB89;
//    pMd5->state[2] = 0X98BADCFE;
//    pMd5->state[3] = 0X10325476;
}


/******************************************************************************
* Function:     Md5Input
*
* Description:  MD5 block update operation. Continues an MD5 message - digest
*               operation, processing another message block, and updating MD5
*
* Returns:      None
******************************************************************************/
void Md5Input
(
    MD5*            pMd5,   // MD5 Context
    const uchar*    pBuffer,// Input bytes
    uint            nCount  // Bytes of input
)
{
    uint   dataCount, chunk;

    // Get count of bytes already in data
    dataCount = (pMd5->countLo) & 0x3F;

    // Update bitcount
    pMd5->countLo += nCount;
    pMd5->countHi += (pMd5->countLo < nCount)&1;

    // Handle any leading odd-sized chunks
    for ( ; (dataCount&3) && nCount; dataCount++, nCount--)
    {
        pMd5->ints[(dataCount)>>2] = (pMd5->ints[(dataCount)>>2]>>8) + (((uint)(*pBuffer++))<<24);
    }

    if (dataCount >= MD5_DATA)
    {
        Md5Round(pMd5); dataCount &= (MD5_DATA-1);
    }

    for ( ; nCount > 3; )
    {
        chunk = MD5_DATA - dataCount;
        if (chunk > nCount)
        {
            chunk = nCount & (-4);
            LByte2Int(pBuffer, &(pMd5->ints[(dataCount>>2)&0x3F]), chunk>>2);
            dataCount += chunk; pBuffer += chunk; nCount -= chunk;
            break;
        }
        else if (chunk)
        {
            LByte2Int(pBuffer, &(pMd5->ints[(dataCount>>2)&0x3F]), chunk>>2);
            dataCount += chunk; pBuffer += chunk; nCount -= chunk;
        }
        Md5Round(pMd5); dataCount &= 0x3F;
    }

    for ( ; nCount; dataCount++, nCount--)
    {
        pMd5->ints[(dataCount>>2)&0x3F] = (pMd5->ints[(dataCount>>2)&0x3F]>>8) + (((uint)(*pBuffer++))<<24);
    }
}


/******************************************************************************
* Function:     Md5Digest
*
* Description:  MD5 finalization. Ends an MD5 message - digest operation, writing
*               the message digest out. The context can continue to take inputs.
*
* Returns:      None.
******************************************************************************/
void Md5Digest
(
    const MD5*  pMd5,               // MD5 Context
    uchar       pDigest[MD5_SIZE]   // digest output
)
{
    uint    count;
    MD5     md5 = *pMd5;

    // Compute number of bytes mod 64
    count = md5.countLo & 0x3F;

    // Set the first char of padding to 0x80.  This is safe since there is
    // always at least one byte free
    md5.ints[(count)>>2] = (md5.ints[(count)>>2]>>8) + (0x80000000); count++;

    for ( ; (count&3); count++)
    {
        md5.ints[(count)>>2] = (md5.ints[(count)>>2]>>8);
    }

    // Pad out to 56 mod 64
    memset(&(md5.ints[count>>2]), 0, MD5_DATA - count);
    if (MD5_DATA - count < 8)
    {
        // Two lots of padding:  Pad the first block to 64 bytes
        Md5Round(&md5);

        // Now fill the next block with 56 bytes
        memset(md5.ints, 0, MD5_DATA);
    }

    // Append length in bits and transform
    md5.ints[14] = (md5.countLo << 3);
    md5.ints[15] = (md5.countHi << 3) + (md5.countLo >> 29);

    Md5Round(&md5);

    Int2LByte(md5.state, pDigest, MD5_SIZE>>2);
}


/******************************************************************************
* Function:     Md5Hash
*
* Description:  Calculate the MD5 hash of a block of message.
*
* Returns:      None
******************************************************************************/
void Md5Hash
(
    const uchar*    pData,
    uint            nSize,
    uchar           pDigest[MD5_SIZE]
)
{
    MD5     md5;

    Md5Init(&md5, NULL);
    Md5Input(&md5, pData, nSize);
    Md5Digest(&md5, pDigest);
}


#ifdef TEST_MD5

#include <stdio.h>
#include <string.h>

typedef struct MD5TEST
{
    const char* pTestString;
    char        result[32];
} MD5TEST;

//Do NOT modify this. This is the official MD5 test suite.
//  See http://tools.ietf.org/html/rfc1321.html
MD5TEST gMD5Tests[] = 
{
    {"",    "D41D8CD98F00B204E9800998ECF8427E"},
    {"a",   "0CC175B9C0F1B6A831C399E269772661"},
    {"abc", "900150983CD24FB0D6963F7D28E17F72"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "8215EF0796A20BCAAAE116D3876C664A"},
    {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57EDF4A22BE3C955AC49DA2E2107B67A"},
    {0, ""}
};


/******************************************************************************
* Function:     md5Test
*
* Description:  Test MD5 message digest against the official test suite.
*
* Returns:      Zero if all test matches. None zero indicates error.
******************************************************************************/
int md5Test()
{
    int         i, j=0;
    MD5         md5;
    MD5TEST*    pTest = gMD5Tests;
    uchar       digest[MD5_SIZE];
    uchar       digestMsg[MD5_SIZE*2+2];

    while (pTest->pTestString && (j == 0))
    {
        Md5Init(&md5, NULL);
        Md5Input(&md5, (const uchar*)pTest->pTestString, strlen(pTest->pTestString));
        Md5Digest(&md5, digest);

        for (i=0; i<MD5_SIZE; i++)
        {
            sprintf((char*)&(digestMsg[i+i]), "%02X", digest[i]);
        }
        j |= memcmp(digestMsg, pTest->result, sizeof(pTest->result));

        pTest++;
    }

    return j;
}

#endif //TEST_MD5
