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
*  File Name:       hmac.c
*
*  Description:     Implementation of HMAC: Keyed-Hashing for Message Authentication
*                   according to RFC2104:   http://www.ietf.org/rfc/rfc2104.txt
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         6/28/2014 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <string.h>
#include <stdint.h>

#include "ssl_int.h"
#include "hmac.h"
#include "cipher.h"


/******************************************************************************
* Function:     HMAC_InitMD5
*
* Description:  Initialize the MD5 portion of HMAC.
*
* Returns:      None.
******************************************************************************/
void HMAC_InitMD5
(
    HMAC*           pHMAC,
    uchar           hashBlock[BLOCK_LEN],
    const VDATA*    pKeyBlock
)
{
    uint i;
    const CIPHER*   pMd5 = &(gpCipherSet->md5);

    memset(hashBlock, 0, BLOCK_LEN);
    memcpy(hashBlock, pKeyBlock->pData, pKeyBlock->nSize);

    pMd5->Init(&(pHMAC->md5a), pMd5->pIData);

    for (i=0; i<BLOCK_LEN; i++)
    {
        hashBlock[i] ^= OPAD_CHAR;   //OPAD byte 0x5C. IPAD byte 0x36
    }
    pMd5->Input(&(pHMAC->md5a),  hashBlock, BLOCK_LEN);
    pMd5->Init(&(pHMAC->md5b), pMd5->pIData);

    for (i=0; i<BLOCK_LEN; i++)
    {
        hashBlock[i] ^= (OPAD_CHAR ^ IPAD_CHAR);  //OPAD 0x5C. IPAD 0x36
    }
    pMd5->Input(&(pHMAC->md5b),  hashBlock, BLOCK_LEN);
}


/******************************************************************************
* Function:     HMAC_InitSHA1
*
* Description:  Initialize the SHA-1 portion of HMAC.
*
* Returns:      None.
******************************************************************************/
void HMAC_InitSHA1
(
    HMAC*           pHMAC,
    uchar           hashBlock[BLOCK_LEN],
    const VDATA*    pKeyBlock
)
{
    uint i;
    const CIPHER*   pSha = &(gpCipherSet->sha1);

    memset(hashBlock, 0, BLOCK_LEN);
    memcpy(hashBlock, pKeyBlock->pData, pKeyBlock->nSize);

    pSha->Init(&(pHMAC->sha1a), pSha->pIData);
    for (i=0; i<BLOCK_LEN; i++)
    {
        hashBlock[i] ^= OPAD_CHAR;   //OPAD byte 0x5C. IPAD byte 0x36
    }

    pSha->Input(&(pHMAC->sha1a), hashBlock, BLOCK_LEN);
    pSha->Init(&(pHMAC->sha1b), pSha->pIData);

    for (i=0; i<BLOCK_LEN; i++)
    {
        hashBlock[i] ^= (OPAD_CHAR ^ IPAD_CHAR);  //OPAD 0x5C. IPAD 0x36
    }

    pSha->Input(&(pHMAC->sha1b), hashBlock, BLOCK_LEN);
}


/******************************************************************************
* Function:     HMAC_MD5
*
* Description:  HMAC calculation using MD5 hash.
*
* Returns:      None.
******************************************************************************/
void HMAC_MD5
(
    HMAC*           pHMAC,
    uchar           md5Hash[MD5_SIZE],
    const VDATA*    pDataBlocks
)
{
    MD5             md5;
    const CIPHER*   pMd5 = &(gpCipherSet->md5);

    md5 = pHMAC->md5b;
    while (pDataBlocks->pData != (uchar*)0)
    {
        pMd5->Input(&md5, pDataBlocks->pData, pDataBlocks->nSize);
        pDataBlocks++;
    }
    pMd5->Digest(&md5, md5Hash);

    md5 = pHMAC->md5a;
    pMd5->Input(&md5, md5Hash, MD5_SIZE);
    pMd5->Digest(&md5, md5Hash);
}


/******************************************************************************
* Function:     HMAC_SHA1
*
* Description:  HMAC calculation using SHA-1 hash.
*
* Returns:      None.
******************************************************************************/
void HMAC_SHA1
(
    HMAC*           pHMAC,
    uchar           shaHash[SHA1_SIZE],
    const VDATA*    pDataBlocks
)
{
    SHA     sha1;
    const CIPHER* pSha = &(gpCipherSet->sha1);

    sha1 = pHMAC->sha1b;
    while (pDataBlocks->pData != (uchar*)0)
    {
        pSha->Input(&sha1, pDataBlocks->pData, pDataBlocks->nSize);
        pDataBlocks++;
    }
    pSha->Digest(&sha1, shaHash);

    sha1 = pHMAC->sha1a;
    pSha->Input(&sha1, shaHash, SHA1_SIZE);
    pSha->Digest(&sha1, shaHash);
}
