import {MAX_UNSIGNED_VALUE} from 'long';
import crypto from 'crypto';
import {BigNumber} from 'bignumber';

const feistelMin = 100;
const numRounds = 10;
const BLOCK_SIZE = 16;
const HALF_BLOCK_SIZE = BLOCK_SIZE / 2;
const MaxBase = 36; 
const maxUint32 = 0xFFFFFFFF;
const aesAlgorithm = ['aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc'];

// For all AES-CBC calls, IV is always 0
const ivZero = new Uint8Array(BLOCK_SIZE);

// ErrStringNotInRadix is returned if input or intermediate strings cannot be parsed in the given radix
const ErrStringNotInRadix = Error('string is not within base/radix');

// ErrTweakLengthInvalid is returned if the tweak length is not in the given range
const ErrTweakLengthInvalid = Error('tweak must be between 0 and given maxTLen, inclusive');

// Need this for the SetIV function which CBCEncryptor has, but cipher.BlockMode interface doesn't.
// TODO: (TRANSLATE) to javascript
// interface cbcMode {
//    cipher.BlockMode
//    SetIV: Uint8Array[],
// }

function toInteger(x) {
  x = Number(x);
  return x < 0 ? Math.ceil(x) : Math.floor(x);
}

function modulo(a, b) {
  return a - Math.floor(a / b) * b;
}

function toUint32(x) {
  return modulo(toInteger(x), Math.pow(2, 32));
}

function toUint16 (n) {
    return n & 0xFFFF;
}

function toUint8 (n) {
    return n & 0xFF;
}

function getUint32FirstByte(uint32) {
    return toUint8((uint32 >>> 24));
}

function getUint32SecondByte(uint32) {
    return toUint8((uint32 >>> 16) & 0xFF);
}

function getUint32ThirdByte(uint32) {
    return toUint8((uint32 >>> 8) & 0xFF);
}

function getUint32LastByte(uint32) {
    return toUint8(uint32 & 0xFF);
}

function setBytes(buf, start, end) {
    let ret = BigNumber(0);
    for (let i = start; i < end; i++) {
        ret <<= 8;
        try {
            ret = ret.plus(BigNumber(buf[i]));
        }
        catch(e) {
            throw e;
        }
    }
    return ret;
}

// returns the absolute value of BigNumber x as a big-endian byte slice.
function toBytesArray(x) {
    let ax = x.abs();
    let ret = [];
    while(ax > 0) {
        ret.unshift(ax&0xff);
        ax >>>= 8;
    }
    return ret;
}

// copy() will copy elements in place from the src into the dst slice (start, end)
function copy(dst, start, end, src) {
    let index = start;
    for (let t of src) {
        if (index >= end) {
            return;
        }
        dst[index] = t;
        index++;
    }
}

class ArrayPointer {
    constructor(buf, begin, end) {
        this.buf = buf;
        this.begin = begin;
        this.end = end;
    }

    copy(start, end, src) {
        copy(this.buf, this.begin + start, this.begin + end, src);
    }

    slice(start, end) {
        return new ArrayPointer(this.buf, this.begin + start, this.begin + end);
    }

    get length() {
        return this.end - this.begin;
    }

    assign(i, value) {
        this.buf[this.begin + i] = value;
    }

    at(i) {
        this.buf[this.begin + i];
    }
};

// NewCipher initializes a new FF1 Cipher for encryption or decryption use
// based on the radix, max tweak length, key and tweak parameters.
module.exports = class FF1Cipher {
    /**
     * radix   int
     * maxTLen int
     * key     []Uint8Array
     * tweak   []Uint8Array
     * return Cipher
     */
    constructor(radix, maxTLen, key, tweak) {
        this.radix = radix;
        this.maxTLen = maxTLen;
        this.tweak = tweak;
        // While FF1 allows radices in [2, 2^16],
        // realistically there's a practical limit based on the alphabet that can be passed in
        if (radix < 2 || radix > MaxBase) {
            throw new Error('radix must be between 2 and 36, inclusive');
        }

        // Make sure the length of given tweak is in range
        if (tweak.length > maxTLen) {
            throw ErrTweakLengthInvalid;
        }

        // Calculate minLength
        this.minLen = toUint32(Math.ceil(Math.log(feistelMin) / Math.log(radix)));
        this.maxLen = maxUint32;

        // Make sure 2 <= minLength <= maxLength < 2^32 is satisfied
        if (this.minLen < 2 || this.maxLen < this.minLen || this.maxLen > maxUint32) {
            throw new Error('minLen invalid, adjust your radix');
        }

        // TODO: (CHECK) with original go code below
        // Now aesBlock uses cbc only, but there is a chance (?) of using ecb as said in comments in ciph() method.
        // GO: aesBlock, err := aes.NewCipher(key)
        // if err != nil {
        //      return newCipher, errors.New("failed to create AES block")
        // }
        // cbcEncryptor := cipher.NewCBCEncrypter(aesBlock, ivZero)

        try {
            switch (key.length) {
                case 16:
                    this.cbcEncryptor = crypto.createCipheriv(aesAlgorithm[0], key, ivZero);
                    break;
                case 24:
                    this.cbcEncryptor = crypto.createCipheriv(aesAlgorithm[1], key, ivZero);
                    break;
                case 32:
                    this.cbcEncryptor = crypto.createCipheriv(aesAlgorithm[2], key, ivZero);
                    break;
                default:
                    throw new Error('key length must be 128, 192, or 256 bits');
            }
        } catch (e) {
            throw new Error('failed to create AES CBC cipher');
        }
        this.cbcEncryptor.setAutoPadding(false);
        // Re-usable CBC encryptor with exported SetIV function
        // cbcEncryptor cipher.BlockMode
    }

    // Encrypt encrypts the string X over the current FF1 parameters
    // and returns the ciphertext of the same length and format

    encrypt(X) {
        return this.encryptWithTweak(X, this.tweak);
    }
      
    // EncryptWithTweak is the same as Encrypt except it uses the
    // tweak from the parameter rather than the current Cipher's tweak
    // This allows you to re-use a single Cipher (for a given key) and simply
    // override the tweak for each unique data input, which is a practical
    // use-case of FPE for things like credit card numbers.
    encryptWithTweak(X, tweak) {
        // n is of uint32
        const n = toUint32(X.length);
        const t = tweak.length;
    
        // Check if message length is within minLength and maxLength bounds
        if (n < this.minLen || n > this.maxLen) {
            throw new Error('message length is not within min and max bounds');
        }
    
        // Make sure the length of given tweak is in range
        if (tweak.length > this.maxTLen) {
            throw ErrTweakLengthInvalid;
        }
    
        const radix = this.radix;
    
        // Check if the message is in the current radix
        let numX = BigNumber(0);
        try {
            numX = BigNumber(X, radix);
        } catch(e) {
            throw ErrStringNotInRadix;
        }
    
        // Calculate split point. n is uint32
        const u = n / 2;
        const v = n - u;
    
        // Split the message
        const A = X.slice(0, u);
        const B = X.slice(u, X.length);
    
        // Byte lengths
        // b is the length of the half input in bytes
        const b = Math.ceil(Math.ceil(v * Math.log2(radix)) / 8);
        // d ?
        const d = 4 * Math.ceil(b / 4) + 4;
    
        // size in 16 bytes blocks
        const maxJ = Math.ceil(d / 16);
    
        const numPad = (-t - b - 1) % 16;
        if (numPad < 0) {
            numPad += 16;
        }
    
        // Calculate P, doesn't change in each loop iteration
        // P's length is always 16, so it can stay on the stack, separate from buf
        const lenP = BLOCK_SIZE;
    
        // p size = blockSize
        const P = function() {
            // in Go: p is a Uint8Array(blockSize)
            // radix must fill 3 bytes, so pad 1 zero byte
            const p = [0x01, 0x02, 0x01, 0x00];
            //Go: binary.BigEndian.PutUint16(P[4:6], uint16(radix))
            p.push((toUint16(radix)>>>8));
            p.push(toUint16(radix) & 0xFF);
            p.push(0x0a);
            p.push(toUint8(u)); // overflow does the modulus

            p.push(getUint32FirstByte(n));
            p.push(getUint32SecondByte(n));
            p.push(getUint32ThirdByte(n));
            p.push(getUint32LastByte(n));
            
            const uint32t = toUint32(t);
            p.push(getUint32FirstByte(uint32t));
            p.push(getUint32SecondByte(uint32t));
            p.push(getUint32ThirdByte(uint32t));
            p.push(getUint32LastByte(uint32t));
        
            return p;
        }();
    
        // Determinte lengths of byte slices
    
        // Q's length is known to always be t+b+1+numPad, to be multiple of 16
        const lenQ = t + b + 1 + numPad;
    
        // For a given input X, the size of PQ is deterministic: 16+lenQ
        const lenPQ = lenP + lenQ;
    
        // lenY := blockSize * maxJ
    
        // buf holds multiple components that change in each loop iteration
        // Ensure there's enough space for max(lenPQ, lenY)
        // Q, PQ, and Y (R, xored) will share underlying memory
        // The total buffer length needs space for:
        // Q (lenQ)
        // PQ (lenPQ)
        // Y = R(last block of PQ) + xored blocks (maxJ - 1)
        const totalBufLen = lenQ + lenPQ + (maxJ-1) * BLOCK_SIZE;
        const buf = new Uint8Array(totalBufLen);
    
        // Q will use the first lenQ bytes of buf
        // Only the last b+1 bytes of Q change for each loop iteration
        let Q = new ArrayPointer(buf, 0, lenQ);// let Q = buf.slice(0, lenQ);
        // This is the fixed part of Q
        // First t bytes of Q are the tweak, next numPad bytes are already zero-valued
        Q.copyToArray(0, t, tweak); // copy(Q, 0, t, tweek);
    
        // Use PQ as a combined storage for P||Q
        // PQ will use the next 16+lenQ bytes of buf
        // Important: PQ is going to be encrypted in place,
        // so P and Q will also remain separate and copied in each iteration
        
        let PQ = new ArrayPointer(buf, lenQ, lenQ + lenPQ); // let PQ = buf.slice(lenQ, lenQ + lenPQ);
    
        // These are re-used in the for loop below
        // variables names prefixed with "num" indicate big integers
        let numA, numB, numC, numY, numU, numV, numModU, numModV = BigNumber(0);
        let numBBytes = new Uint8Array();
        // TODO: (CHECK) make sure numRadix.SetInt64(int64(radix))
        const numRadix = BigNumber(radix);

        // Y starts at the start of last block of PQ, requires lenY bytes
        // R is part of Y, Overlaps part of PQ
        const Y = new ArrayPointer(buf, lenQ + lenPQ - BLOCK_SIZE, buf.length); // const Y = buf.slice(lenQ + lenPQ - BLOCK_SIZE, buf.length);
    
        // R starts at Y, requires blockSize bytes, which uses the last block of PQ
        let R = Y.slice(0, BLOCK_SIZE); // let R = Y.slice(0, BLOCK_SIZE);
        
        // This will only be needed if maxJ > 1, for the inner for loop
        // xored uses the blocks after R in Y, if any
        const xored = Y.slice(BLOCK_SIZE, Y.length); // const xored = Y.slice(BLOCK_SIZE, Y.length);
        
        // Pre-calculate the modulus since it's only one of 2 values,
        // depending on whether i is even or odd
        try {
            numU = BigNumber(u);
            numV = BigNumber(v);

            // PS: in Go big.Exp returns 1 if power is less than 0 while this JS BigNumber library rounds it
            // thus this if statement below is added.
            if (numU.isLessThan(0)) {
                numModU = BigNumber(1);
            } else {
                numModU = numRadix.pow(numU);
            }

            if (numU.isLessThan(0)) {
                numModV = BigNumber(1);
            } else {
                numModV = numRadix.pow(numV);
            }

            // Bootstrap for 1st round

            numA = BigNumber(A, radix);
            numB = BigNumber(B, radix);
        } catch(e) {
            throw ErrStringNotInRadix;
        }
    
        // Main Feistel Round, 10 times
        for (let i = 0; i < numRounds; i++) {
            // Calculate the dynamic parts of Q
            // TODO: (CHECK) with Zhi below
            // original GO: Q[t+numPad] = byte(i)
            Q.assign(t+numPad, toUint8(i));
    
            numBBytes = toBytesArray(numB)
    
            // Zero out the rest of Q
            // When the second half of X is all 0s, numB is 0, so numBytes is an empty slice
            // So, zero out the rest of Q instead of just the middle bytes, which covers the numB=0 case
            // See https://github.com/capitalone/fpe/issues/10
            for (let j = t + numPad + 1; j < lenQ; j++) {
                Q.assign(j, 0x00);
            }
    
            // B must only take up the last b bytes
            Q.copy(lenQ - numBBytes.length, Q.length, numBBytes);
            // copy(Q, lenQ - numBBytes.length, Q.length, numBBytes);
    
            // PQ = P||Q
            // Since prf/ciph will operate in place, P and Q have to be copied into PQ,
            // for each iteration to reset the contents
            PQ.copy(0, BLOCK_SIZE, P);
            // copy(PQ, 0, BLOCK_SIZE, P);
            PQ.copy(BLOCK_SIZE, PQ.length, Q);
            // copy(PQ, BLOCK_SIZE, PQ.length, Q);
    
            // R is guaranteed to be of length 16
            R = this.prf(PQ);

            // Step 6iii
            for (let j = 1; j < maxJ; j++) {
                // offset is used to calculate which xored block to use in this iteration
                const offset = (j - 1) * BLOCK_SIZE;
    
                // Since xorBytes operates in place, xored needs to be cleared
                // Only need to clear the first 8 bytes since j will be put in for next 8
                for (let x = 0; x < HALF_BLOCK_SIZE; x++) {
                    xored.assign(offset + x) = 0x00; // xored[offset + x] = 0x00;
                }
                // TODO: (TRANSLATE) below
                // binary.BigEndian.PutUint64(xored[offset+halfBlockSize:offset+BLOCK_SIZE], uint64(j));
                xored.assign(offset+HALF_BLOCK_SIZE, 0x00);
                xored.assign(offset+HALF_BLOCK_SIZE + 1, 0x00);
                xored.assign(offset+HALF_BLOCK_SIZE + 2, 0x00);
                xored.assign(offset+HALF_BLOCK_SIZE + 3, 0x00);
                const uint32j = toUint32(j);
                xored.assign(offset+HALF_BLOCK_SIZE + 4, getUint32FirstByte(uint32j));
                xored.assign(offset+HALF_BLOCK_SIZE + 5, getUint32SecondByte(uint32j));
                xored.assign(offset+HALF_BLOCK_SIZE + 6, getUint32ThirdByte(uint32j));
                xored.assign(offset+HALF_BLOCK_SIZE + 7, getUint32LastByte(uint32j));
    
                // XOR R and j in place
                // R, xored are always 16 bytes
                for (let x = 0; x < BLOCK_SIZE; x++) {
                    xored.assign(offset+x, R[x] ^ xored.at(offset+x));
                }
    
                // AES encrypt the current xored block
                try {
                    // TODO assign return value to xored
                    this.ciph(xored.slice(offset, offset + BLOCK_SIZE));
                } catch(e) {
                    throw e;
                }
            }
            
            try {
                numY = setBytes(Y, 0, d);
                numC = numA.plus(numY);
                if (i % 2 == 0) {
                    numC = numC.mod(numModU);
                } else {
                    numC = numC.mod(numModV);
                }
                // big.Ints use pointers behind the scenes so when numB gets updated,
                // numA will transparently get updated to it. Hence, set the bytes explicitly
                // TODO: (CHECK) this "numA will transparently get updated to it" thing in JS?
                numA = setBytes(numBBytes, 0, numBBytes.length);
                numB = numC;
            }
            catch(e) {
                throw e;
            }
        }

        A = numA.toString(radix);
        B = numB.toString(radix);

        // Pad both A and B properly
        A = '0'.repeat(u - A.length) + A;
        B = '0'.repeat(v - B.length) + B;
        
        return A + B;
    }      

    // Decrypt decrypts the string X over the current FF1 parameters
    // and returns the plaintext of the same length and format
    Decrypt(X) {
        return DecryptWithTweak(X, this.tweak);
    }
    
    // DecryptWithTweak is the same as Decrypt except it uses the
    // tweak from the parameter rather than the current Cipher's tweak
    // This allows you to re-use a single Cipher (for a given key) and simply
    // override the tweak for each unique data input, which is a practical
    // use-case of FPE for things like credit card numbers.
    DecryptWithTweak(X, tweak) {
        const n = toUint32(X.length);
        const t = tweak.length;
    
        // Check if message length is within minLength and maxLength bounds
        if (n < this.minLen || n > this.maxLen) {
            throw new Error('message length is not within min and max bounds');
        }
    
        // Make sure the length of given tweak is in range
        if (tweak.length > this.maxTLen) {
            throw ErrTweakLengthInvalid;
        }
    
        const radix = this.radix;
    
        // Check if the message is in the current radix
        let numX = BigNumber(0);
        try {
            numX = BigNumber(X, radix);
        } catch(e) {
            throw ErrStringNotInRadix;
        }
    
        // Calculate split point
        const u = n / 2;
        const v = n - u;
    
        // Split the message
        const A = X.slice(0, u);
        const B = X.slice(u, X.length);
    
		// Byte lengths
		// b is the length of the half input in bytes
        const b = Math.ceil(Math.ceil(v * Math.log2(radix)) / 8);
        const d = 4 * Math.ceil(b / 4) + 4;
    
        const maxJ = Math.ceil(d / 16);
    
        let numPad = (-t - b - 1) % 16;
        if (numPad < 0) {
            numPad += 16;
        }
    
        // Calculate P, doesn't change in each loop iteration
        // P's length is always 16, so it can stay on the stack, separate from buf
        const lenP = BLOCK_SIZE;
        const P = function() {
            // in Go: p is a Uint8Array(blockSize)
            // radix must fill 3 bytes, so pad 1 zero byte
            const p = [0x01, 0x02, 0x01, 0x00];
            //Go: binary.BigEndian.PutUint16(P[4:6], uint16(radix))
            p.push((toUint16(radix)>>>8));
            p.push(toUint16(radix) & 0xFF);
            p.push(0x0a);
            p.push(toUint8(u)); // overflow does the modulus

            p.push(getUint32FirstByte(n));
            p.push(getUint32SecondByte(n));
            p.push(getUint32ThirdByte(n));
            p.push(getUint32LastByte(n));
            
            const uint32t = toUint32(t);
            p.push(getUint32FirstByte(uint32t));
            p.push(getUint32SecondByte(uint32t));
            p.push(getUint32ThirdByte(uint32t));
            p.push(getUint32LastByte(uint32t));
        
            return p;
        }();
    
        // Determinte lengths of byte slices
    
        // Q's length is known to always be t+b+1+numPad, to be multiple of 16
        const lenQ = t + b + 1 + numPad;
    
        // For a given input X, the size of PQ is deterministic: 16+lenQ
        const lenPQ = lenP + lenQ;
        
        // buf holds multiple components that change in each loop iteration
        // Ensure there's enough space for max(lenPQ, lenY)
        // Q, PQ, and Y (R, xored) will share underlying memory
        // The total buffer length needs space for:
        // Q (lenQ)
        // PQ (lenPQ)
        // Y = R(last block of PQ) + xored blocks (maxJ - 1)
        const totalBufLen = lenQ + lenPQ + (maxJ-1) * BLOCK_SIZE;
        const buf = new Uint8Array(totalBufLen);
    
        // Q will use the first lenQ bytes of buf
        // Only the last b+1 bytes of Q change for each loop iteration
        let Q = new ArrayPointer(buf, 0, lenQ);// let Q = buf.slice(0, lenQ);
        // This is the fixed part of Q
        // First t bytes of Q are the tweak, next numPad bytes are already zero-valued
        Q.copyToArray(0, t, tweak); // copy(Q, 0, t, tweek);
    
        // Use PQ as a combined storage for P||Q
        // PQ will use the next 16+lenQ bytes of buf
        // Important: PQ is going to be encrypted in place,
        // so P and Q will also remain separate and copied in each iteration
        let PQ = new ArrayPointer(buf, lenQ, lenQ + lenPQ); // let PQ = buf.slice(lenQ, lenQ + lenPQ);
    
        // These are re-used in the for loop below
        // variables names prefixed with "num" indicate big integers
        let numA, numB, numC, numRadix, numY, numU, numV, numModU, numModV = BigNumber(0);
        let numABytes = new Uint8Array();
        // TODO: (CHECK) if BigNumber set it right. All these 'nums' are set to int64.
        // original GO: numRadix.SetInt64(int64(radix))
		const numRadix = BigNumber(radix);
		
        // Y starts at the start of last block of PQ, requires lenY bytes
        // R is part of Y, Overlaps part of PQ
        const Y = new ArrayPointer(buf, lenQ + lenPQ - BLOCK_SIZE, buf.length); // const Y = buf.slice(lenQ + lenPQ - BLOCK_SIZE, buf.length);
    
        // R starts at Y, requires blockSize bytes, which uses the last block of PQ
        let R = Y.slice(0, BLOCK_SIZE);
        
        // This will only be needed if maxJ > 1, for the inner for loop
        // xored uses the blocks after R in Y, if any
        const xored = Y.slice(BLOCK_SIZE, Y.length);
        
        // Pre-calculate the modulus since it's only one of 2 values,
        // depending on whether i is even or odd
        try {
            numU = BigNumber(u);
            numV = BigNumber(v);

            // PS: in Go big.Exp returns 1 if power is less than 0 while this BigNumber rounds the result
            // thus this if statement below is added.
            if (numU.isLessThan(0)) {
                numModU = BigNumber(1);
            } else {
                numModU = numRadix.pow(numU);
            }

            if (numU.isLessThan(0)) {
                numModV = BigNumber(1);
            } else {
                numModV = numRadix.pow(numV);
            }

            // Bootstrap for 1st round
            numA = BigNumber(A, radix);
            numB = BigNumber(B, radix);
        }
        catch(e) {
            throw ErrStringNotInRadix;
        }
    
        // Main Feistel Round, 10 times
    
        for (let i = numRounds - 1; i >= 0; i--) {
            // Calculate the dynamic parts of Q
            Q.assign(t+numPad, toUint8(i));
    
            numABytes = toBytesArray(numA);
            
    
            // Zero out the rest of Q
            // When the second half of X is all 0s, numB is 0, so numBytes is an empty slice
            // So, zero out the rest of Q instead of just the middle bytes, which covers the numB=0 case
            // See https://github.com/capitalone/fpe/issues/10
            for (let j = t + numPad + 1; j < lenQ; j++) {
                Q.assign(j, 0x00);
            }
    
			// B must only take up the last b bytes
			Q.copy(lenQ - numABytes.length, Q.length, numABytes);
    
            // PQ = P||Q
            // Since prf/ciph will operate in place, P and Q have to be copied into PQ,
            // for each iteration to reset the contents
            PQ.copy(0, BLOCK_SIZE, P);
            PQ.copy(BLOCK_SIZE, PQ.length, Q);
    
            // R is guaranteed to be of length 16
            R = this.prf(PQ);
    
            // Step 6iii
            for (let j = 1; j < maxJ; j++) {
                // offset is used to calculate which xored block to use in this iteration
                const offset = (j - 1) * BLOCK_SIZE;
    
                // Since xorBytes operates in place, xored needs to be cleared
                // Only need to clear the first 8 bytes since j will be put in for next 8
                for (let x = 0; x < HALF_BLOCK_SIZE; x++) {
                    xored.assign(offset + x) = 0x00; // xored[offset + x] = 0x00;
                }
                // TODO: (TRANSLATE) to JS
                // binary.BigEndian.PutUint64(xored[offset+halfBlockSize:offset+blockSize], uint64(j));
                xored.assign(offset+HALF_BLOCK_SIZE, 0x00);
                xored.assign(offset+HALF_BLOCK_SIZE + 1, 0x00);
                xored.assign(offset+HALF_BLOCK_SIZE + 2, 0x00);
                xored.assign(offset+HALF_BLOCK_SIZE + 3, 0x00);
                const uint32j = toUint32(j);
                xored.assign(offset+HALF_BLOCK_SIZE + 4, getUint32FirstByte(uint32j));
                xored.assign(offset+HALF_BLOCK_SIZE + 5, getUint32SecondByte(uint32j));
                xored.assign(offset+HALF_BLOCK_SIZE + 6, getUint32ThirdByte(uint32j));
                xored.assign(offset+HALF_BLOCK_SIZE + 7, getUint32LastByte(uint32j));
 
                // XOR R and j in place
                // R, xored are always 16 bytes
                for (let x = 0; x < BLOCK_SIZE; x++) {
                    xored.assign(offset+x, R[x] ^ xored.at(offset+x));
                }
    
                // AES encrypt the current xored block
                try {
                    this.ciph(xored.slice(offset, offset + BLOCK_SIZE));
                } catch(e) {
                    throw e;
                }
            }


            try {
                numY = setBytes(Y, 0, d);
                numC = numB.minus(numY);
                if (i % 2 == 0) {
                    numC = numC.mod(numModU);
                } else {
                    numC = numC.mod(numModV);
                }

                // big.Ints use pointers behind the scenes so when numB gets updated,
                // numA will transparently get updated to it. Hence, set the bytes explicitly
                // TODO: (CHECK) this "numA will transparently get updated to it" thing in JS
                numB = setBytes(numABytes, 0, numABytes.length);
                numA = numC;
            } catch(e) {
                throw e;
            }
        }

        A = numA.toString(radix);
        B = numB.toString(radix);
    
        // Pad both A and B properly
        A = '0'.repeat(u - A.length) + A;
        B = '0'.repeat(v - B.length) + B;
    
        ret = A + B;
    
        return ret;
    }

    // ciph defines how the main block cipher is called.
    // When prf calls this, it will likely be a multi-block input, in which case ciph behaves as CBC mode with IV=0.
    // When called otherwise, it is guaranteed to be a single-block (16-byte) input because that's what the algorithm dictates. In this situation, ciph behaves as ECB mode
    ciph(input) {
        // These are checked here manually because the CryptBlocks function panics rather than returning an error
        // So, catch the potential error earlier
        if (input.length % BLOCK_SIZE !== 0) {
            throw new Error('length of ciph input must be multiple of 16');
        }
        // TODO: (TRANSLATE) code below
        // this.cbcEncryptor.CryptBlocks(input, input);
        let retval = this.cbcEncryptor.update(input);
        retval += this.cbcEncryptor.final();
        // Reset IV to 0
        // TODO: (TRANSLATE) code below
        // this.cbcEncryptor.(cbcMode).SetIV(ivZero);
    
        return retval;
    
    }
    
    // PRF as defined in the NIST spec is actually just AES-CBC-MAC, which is the last block of an AES-CBC encrypted ciphertext. Utilize the ciph function for the AES-CBC.
    // PRF always outputs 16 bytes (one block)
    prf(input) {
        try {
            const cipher = this.ciph(input);
            return cipher.slice(cipher.length - BLOCK_SIZE, cipher.length);
        } catch(e) {
            throw e;
        }
    }
}
