/*
 * crypto.c - Source file
 * Crypt or decrypt given block. XXTEA cipher is used.
 * Based on: 
 * David J. Wheeler and Roger M. Needham (October 1998). "Correction to XTEA".
 * Computer Laboratory, Cambridge University, England.
 * Author: Vlastimil Kosar <ikosar@fit.vutbr.cz> 
 */

#include <stdint.h>
#include "crypto.h"

/*
 * Decrypt block by XXTEA.
 * Params:
 *   block - block of encrypted data
 *   len   - length of block
 *   key   - 128b key
 */
void decrypt(uint32_t *block, uint32_t len, uint32_t *key)
{
    uint32_t z=block[len-1], y=block[0], sum=0, e, DELTA=0x9e3779b9;
    int32_t p, q;
    
    q = 6 + 52/len;
    sum = q*DELTA ;
    while (sum != 0) {
        e = (sum >> 2) & 3;
        for (p=len-1; p>0; p--)
        {
            z = block[p-1];
            block[p] -= (z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (key[p&3^e]^z);
            y = block[p];
        }
        z = block[len-1];
        block[0] -= (z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (key[p&3^e]^z);
        y =  block[0];
        sum -= DELTA;
    }
}

/*
 * Crypt block by XXTEA.
 * Params:
 *   block - block of input data
 *   len   - length of block
 *   key   - 128b key
 */
void crypt(uint32_t *block, uint32_t len, uint32_t *key)
{
    uint32_t z=block[len-1], y=block[0], sum=0, e, DELTA=0x9e3779b9;
    int32_t p, q;
    
    q = 6 + 52/len;
    while (q-- > 0) {
        sum += DELTA;
        e = (sum >> 2) & 3;
        for (p=0; p<len-1; p++)
        {
            y = block[p+1];
            block[p] += (z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (key[p&3^e]^z);
            z = block[p];
        }
        y = block[0];
        block[len-1] += (z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (key[p&3^e]^z);
        z = block[len-1];
    }
}