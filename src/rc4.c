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
*  File Name:       rc4.c
*
*  Description:     The RC4 cipher, as first revealed on the web in 1994. See
*                   http://www.columbia.edu/~ariel/ssleay/rrc4.html
*
*  Programmers:     Anthony Mai (am) mai_anthony@hotmail.com
*
*  History:         6/27/2014 Initial creation
*
*  Notes:           This file uses 4 spaces indents
*
******************************************************************************/

#include <stdint.h>
#include "rc4.h"


/******************************************************************************
* Function:     RC4Init
*
* Description:  Initialize RC4 engine for data encryption/decryption.
*
* Returns:      None.
******************************************************************************/
void RC4Init
(
    RC4*            pCtx,
    const uchar*    pKey,
    uint            nKeyLen
)
{
    uchar   swapByte;
    uchar   index1;
    uchar   index2;
    uchar*  state;
    uint    count;
    
    state = &(pCtx->state[0]);
    for(count = 0; count < sizeof(pCtx->state); count++)
    {
        state[count] = (uchar)count;
    }

    pCtx->x = pCtx->y = 0;

    index1 = index2 = 0;

    for(count = 0; count < 256; count++)
    {
        swapByte = state[count];
        index2 += pKey[index1] + swapByte;
        // Swap byte state[counter] and state[index2].
        state[count] = state[index2];
        state[index2] = swapByte;

        index1 = (index1 + 1) % nKeyLen;
    }
}


/******************************************************************************
* Function:     RC4Code
*
* Description:  Do RC4 encryption or decryption of a chunk of data.
*
* Returns:      None.
******************************************************************************/
void RC4Code
(
    RC4*    pCtx,
    uchar*  pData,
    uint    nLen
)
{
    uchar   x;
    uchar   y;
    uchar*  state;
    uchar   xorIndex;
    uint    count;

    x = pCtx->x; y = pCtx->y;

    state = &pCtx->state[0];         
    for(count = 0; count < nLen; count ++)
    {
         x ++;
         y += state[x];

         xorIndex = state[x] + state[y];

         //swap the byte state[x] and state[y].
         state[x] = xorIndex - state[x];
         state[y] = xorIndex - state[y];

         pData[count] ^= state[xorIndex];
     }
     pCtx->x = x; pCtx->y = y;
}


#ifdef TEST_RC4
#include <memory.h>

//   Test vector 0
//   Key: 0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef 
//   Input: 0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef 
//   0 Output: 0x75 0xb7 0x87 0x80 0x99 0xe0 0xc5 0x96 
//   
//   Test vector 1
//   Key: 0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef 
//   Input: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 
//   0 Output: 0x74 0x94 0xc2 0xe7 0x10 0x4b 0x08 0x79 
//   
//   Test vector 2
//   Key: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 
//   Input: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 
//   0 Output: 0xde 0x18 0x89 0x41 0xa3 0x37 0x5d 0x3a 


//   Test vector 3
static uchar gKey3[] = {0xef, 0x01, 0x23, 0x45};

static uchar gInput3[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static uchar gOutput3[] = {
    0xd6, 0xa1, 0x41, 0xa7, 0xec, 0x3c, 0x38, 0xdf, 0xbd, 0x61
};


/******************************************************************************
* Function:     rc4Test
*
* Description:  Run a suite of RC4 encryption/decryption test.
*
* Returns:      Zero if no error.
******************************************************************************/
int rc4Test()
{
    uint    ret = 0;
    RC4     ctx;

    RC4Init(&ctx, gKey3, sizeof(gKey3));
    RC4Code(&ctx, gInput3, sizeof(gInput3));

    ret |= memcmp(gInput3, gOutput3, sizeof(gInput3));

    return ret;
}


#endif //TEST_RC4
