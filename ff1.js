import {MAX_UNSIGNED_VALUE} from 'long';
import crypto from 'crypto';
import {BigNumber} from 'bignumber';

const feistelMin = 100;
const numRounds = 10;
const blockSize = 16;
const halfBlockSize = blockSize / 2;
const MaxBase = 36; 
const maxUint32 = 0xFFFFFFFF;
const aesAlgorithm = ['aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc'];

// For all AES-CBC calls, IV is always 0
const ivZero = new Uint8Array(blockSize);

// ErrStringNotInRadix is returned if input or intermediate strings cannot be parsed in the given radix
const ErrStringNotInRadix = Error('string is not within base/radix');

// ErrTweakLengthInvalid is returned if the tweak length is not in the given range
const ErrTweakLengthInvalid = Error('tweak must be between 0 and given maxTLen, inclusive');

// Need this for the SetIV function which CBCEncryptor has, but cipher.BlockMode interface doesn't.
// TODO: translate to javascript
interface cbcMode {
    cipher.BlockMode
    SetIV: Uint8Array[],
}

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

// NewCipher initializes a new FF1 Cipher for encryption or decryption use
// based on the radix, max tweak length, key and tweak parameters.
module.exports = {
	NewCipher(radix, maxTLen, key, tweak) {
		/*
			radix   int
			maxTLen int
			key     []Uint8Array
			tweak   []Uint8Array

			return Cipher
		*/
		const keyLen = key.length;

		// Check if the key is 128, 192, or 256 bits = 16, 24, or 32 bytes
		if (keyLen !== 16 && keyLen !== 24 && keyLen !== 32) {
			throw new Error('key length must be 128, 192, or 256 bits');
		}

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
		const minLen = toUint32(Math.ceil(Math.log(feistelMin) / Math.log(radix)));
		const maxLen = maxUint32;

		// Make sure 2 <= minLength <= maxLength < 2^32 is satisfied
		if (minLen < 2 || maxLen < minLen || maxLen > maxUint32) {
			throw new Error('minLen invalid, adjust your radix');
		}

		// TODO: Check with original go code below
		// Now aesBlock uses cbc only, but there is a chance (?) of using ecb as said in comments in ciph() method.
		// GO: aesBlock, err := aes.NewCipher(key)
		// if err != nil {
		// 	 return newCipher, errors.New("failed to create AES block")
		// }
		// cbcEncryptor := cipher.NewCBCEncrypter(aesBlock, ivZero)

		let aesBlock = undefined;
		try {
			switch(key.length) {
				case 16:
					aesBlock = crypto.createCipheriv(aesAlgorithm[0], key, ivZero);
					break;
				case 24:
					aesBlock = crypto.createCipheriv(aesAlgorithm[1], key, ivZero);
					break;
				case 32:
					aesBlock = crypto.createCipheriv(aesAlgorithm[2], key, ivZero);
					break;
				default:
					throw new Error('key length must be 128, 192, or 256 bits');
			}
			const cbcEncryptor = aesBlock; // TODO: ?
			return new Cipher(tweak, radix, minLen, maxLen, maxTLen, cbcEncryptor);
		} catch (e) {
			throw new Error('failed to create AES block');
		}
	},
};

class Cipher {
	constructor(tweak, radix, minLen, maxLen, maxTLen, cbcEncryptor) {
		this.tweak = tweak;
		this.radix = radix;
		this.minLen = minLen;
		this.maxLen = maxLen;
		this.maxTLen = maxTLen;
		
		// Re-usable CBC encryptor with exported SetIV function
		// cbcEncryptor cipher.BlockMode
		this.cbcEncryptor = cbcEncryptor;
	}

	// Encrypt encrypts the string X over the current FF1 parameters
	// and returns the ciphertext of the same length and format

	Encrypt(X) {
		return this.EncryptWithTweak(X, this.tweak);
	  }
	  
	// EncryptWithTweak is the same as Encrypt except it uses the
	// tweak from the parameter rather than the current Cipher's tweak
	// This allows you to re-use a single Cipher (for a given key) and simply
	// override the tweak for each unique data input, which is a practical
	// use-case of FPE for things like credit card numbers.
	EncryptWithTweak(X, tweak) {
		let ret = '';
	  
		// n is of uint32
		const n = (X.length) >>> 0;
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
		}
		catch (error) {
			throw ErrStringNotInRadix;
		}
	
		// Calculate split point
		const u = n / 2;
		const v = n - u;
	
		// Split the message
		const A = X.slice(0, u);
		const B = X.slice(u, X.length);
	
		// Byte lengths
		const b = Math.ceil(Math.ceil(v * Math.log2(radix)) / 8);
		const d = 4 * Math.ceil(b / 4) + 4;
	
		const maxJ = Math.ceil(d / 16);
	
		const numPad = (-t - b - 1) % 16;
		if (numPad < 0) {
			numPad += 16;
		}
	
		// Calculate P, doesn't change in each loop iteration
		// P's length is always 16, so it can stay on the stack, separate from buf
		const lenP = blockSize;
	
		// p size = blockSize
		const P = () => {
			// in Go: p is a Uint8Array(blockSize)
			 // radix must fill 3 bytes, so pad 1 zero byte
			const p = [0x01, 0x02, 0x01, 0x00];
			//Go: binary.BigEndian.PutUint16(P[4:6], uint16(radix))
			p.push((toUint16(radix)>>>8));
			p.push(toUint16(radix) & 0xFF);
			p.push(0x0a);
			p.push(toUint8(u)); // overflow does the modulus

			p.push(toUint32(n)>>>24);
			p.push((toUint32(n)>>>16) & 0xff);
			p.push((toUint32(n) & 0xffff)>>>8);
			p.push(toUint32(n) & 0xFF);

			p.push(toUint32(t)>>>24);
			p.push((toUint32(t)>>>16) & 0xff);
			p.push((toUint32(t) & 0xffff)>>>8);
			p.push(toUint32(t) & 0xFF);
		
			return p;
		  };
	
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
		const totalBufLen = lenQ + lenPQ + (maxJ-1) * blockSize;
		const buf = new Uint8Array(totalBufLen);
	
		// Q will use the first lenQ bytes of buf
		// Only the last b+1 bytes of Q change for each loop iteration
		let Q = buf.slice(0, lenQ);
		// This is the fixed part of Q
		// First t bytes of Q are the tweak, next numPad bytes are already zero-valued
		copy(Q, 0, t, tweak);
	
		// Use PQ as a combined storage for P||Q
		// PQ will use the next 16+lenQ bytes of buf
		// Important: PQ is going to be encrypted in place,
		// so P and Q will also remain separate and copied in each iteration
		let PQ = buf.slice(lenQ, lenQ + lenPQ);
	
		// These are re-used in the for loop below
		// variables names prefixed with "num" indicate big integers
		let numA, numB, numC, numRadix, numY, numU, numV, numModU, numModV = BigNumber(0);
		let numBBytes = new Uint8Array();
		// TODO: make sure numRadix.SetInt64(int64(radix))
		try {
			numRadix = BigNumber(radix);
		}
		catch (error) {
			throw error;
		}

		// Y starts at the start of last block of PQ, requires lenY bytes
		// R is part of Y, Overlaps part of PQ
		const Y = buf.slice(lenQ + lenPQ - blockSize, buf.length);
	
		// R starts at Y, requires blockSize bytes, which uses the last block of PQ
		let R = Y.slice(0, blockSize);
		
		// This will only be needed if maxJ > 1, for the inner for loop
		// xored uses the blocks after R in Y, if any
		const xored = Y.slice(blockSize, Y.length);
		
		// Pre-calculate the modulus since it's only one of 2 values,
		// depending on whether i is even or odd
		try {
			numU = BigNumber(u);
			numV = BigNumber(v);
		}
		catch (error) {
			throw error;
		}

		// PS: in Go big.Exp returns 1 if power is less than 0 while this JS BigNumber library rounds it
		// thus this if statement below is added.
		if (numU.isLessThan(0)) {
			numModU = BigNumber(1);
		} else {
			try {
				numModU = numRadix.pow(numU);
			}
			catch (error) {
				throw error;
			}
		}

		if (numU.isLessThan(0)) {
			numModV = BigNumber(1);
		} else {
			try {
				numModV = numRadix.pow(numV);
			}
			catch (error) {
				throw error;
			}
		}
		
		// Bootstrap for 1st round
	
		try {
			numA = BigNumber(A, radix);
		}
		catch (error) {
			throw ErrStringNotInRadix;
		}

		try {
			numB = BigNumber(B, radix);
		}
		catch (error) {
			throw ErrStringNotInRadix;
		}
	
		// Main Feistel Round, 10 times
	
		for (let i = 0; i < numRounds; i++) {
			// Calculate the dynamic parts of Q
			// TODO: check with Zhi below
			// original GO: Q[t+numPad] = byte(i)
			Q[t+numPad] = toUint8(i);
	
			// TODO: translate to js. Bytes returns the absolute value of x as a big-endian byte slice.
			numBBytes = numB.Bytes();
	
			// Zero out the rest of Q
			// When the second half of X is all 0s, numB is 0, so numBytes is an empty slice
			// So, zero out the rest of Q instead of just the middle bytes, which covers the numB=0 case
			// See https://github.com/capitalone/fpe/issues/10
			for (let j = t + numPad + 1; j < lenQ; j++) {
				Q[j] = 0x00;
			}
	
			// B must only take up the last b bytes
			copy(Q, lenQ - numBBytes.length, Q.length, numBBytes);
	
			// PQ = P||Q
			// Since prf/ciph will operate in place, P and Q have to be copied into PQ,
			// for each iteration to reset the contents
			copy(PQ, 0, blockSize, P);
			copy(PQ, blockSize, PQ.length, Q);
	
			// R is guaranteed to be of length 16
			try {
				R = this.prf(PQ);
			}
			catch (error) {
				throw error;
			}

			// Step 6iii
			for (let j = 1; j < maxJ; j++) {
				// offset is used to calculate which xored block to use in this iteration
				const offset = (j - 1) * blockSize;
	
				// Since xorBytes operates in place, xored needs to be cleared
				// Only need to clear the first 8 bytes since j will be put in for next 8
				for (let x = 0; x < halfBlockSize; x++) {
					xored[offset + x] = 0x00;
				}
				// TODO: translate below
				binary.BigEndian.PutUint64(xored[offset+halfBlockSize:offset+blockSize], uint64(j));
	
				// XOR R and j in place
				// R, xored are always 16 bytes
				for (let x = 0; x < blockSize; x++) {
					xored[offset+x] = R[x] ^ xored[offset+x];
				}
	
				// AES encrypt the current xored block
				try {
					this.ciph(xored.slice(offset, offset + blockSize));
				}
				catch (error) {
					throw error;
				}
			}
			// TODO: translate. SetBytes interprets buf as the bytes of a big-endian unsigned integer, sets z to that value, and returns z.
			numY.SetBytes(Y.slice(0, d));
			
			numC = numA.add(numY);

			if (i % 2 == 0) {
				numC = numC.mod(numModU);
			} else {
				numC = numC.mod(numModV);
			}
	
			// big.Ints use pointers behind the scenes so when numB gets updated,
			// numA will transparently get updated to it. Hence, set the bytes explicitly
			// TODO: check this "numA will transparently get updated to it" thing in JS
			
			// TODO: SetBytes interprets buf as the bytes of a big-endian unsigned integer, sets z to that value, and returns z.
			numA.SetBytes(numBBytes);
			numB = numC;
		}

		A = numA.toString(radix);
		B = numB.toString(radix);
	
		// Pad both A and B properly
		A = '0'.repeat(u - A.length) + A;
		B = '0'.repeat(v - B.length) + B;
	
		ret = A + B;
	
		return ret;
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
		let ret = '';
		
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
	
		return DecryptWithTweakMain(X, tweak, n, t, ret);
	}
	
	DecryptWithTweakMain(X, tweak, n, t, ret) {
		const radix = this.radix;
	
		// Check if the message is in the current radix
		let numX = BigNumber(0);
		try {
			numX = BigNumber(X, radix);
		}
		catch (error) {
			throw ErrStringNotInRadix;
		}
	
		// Calculate split point
		const u = n / 2;
		const v = n - u;
	
		// Split the message
		let A = X.substring(0, u);
		let B = X.substring(u);
	
		// Byte lengths
		const b = Math.ceil(Math.ceil(v * Math.log2(radix)) / 8);
		const d = 4 * Math.ceil(b / 4) + 4;
	
		const maxJ = Math.ceil(d / 16);
	
		let numPad = (-t - b - 1) % 16;
		if (numPad < 0) {
			numPad += 16;
		}
	
		// Calculate P, doesn't change in each loop iteration
		// P's length is always 16, so it can stay on the stack, separate from buf
		const lenP = blockSize;
		const P = () => {
			// in Go: p is a Uint8Array(blockSize)
			// radix must fill 3 bytes, so pad 1 zero byte
			const p = [0x01, 0x02, 0x01, 0x00];
			p.push((toUint16(radix)>>>8));
			p.push(toUint16(radix) & 0xFF);
			p.push(0x0a);
			p.push(toUint8(u)); // overflow automatically does the modulus

			p.push(toUint32(n)>>>24);
			p.push((toUint32(n)>>>16) & 0xff);
			p.push((toUint32(n) & 0xffff)>>>8);
			p.push(toUint32(n) & 0xFF);

			p.push(toUint32(t)>>>24);
			p.push((toUint32(t)>>>16) & 0xff);
			p.push((toUint32(t) & 0xffff)>>>8);
			p.push(toUint32(t) & 0xFF);
		
			return p;
		};
	
		// Determinte lengths of byte slices
	
		// Q's length is known to always be t+b+1+numPad, to be multiple of 16
		const lenQ = t + b + 1 + numPad;
	
		// For a given input X, the size of PQ is deterministic: 16+lenQ
		const lenPQ = lenP + lenQ;
		
		const totalBufLen = lenQ + lenPQ + (maxJ-1) * blockSize;
		const buf = new Uint8Array(totalBufLen);
	
		// Q will use the first lenQ bytes of buf
		// Only the last b+1 bytes of Q change for each loop iteration
		let Q = buf.slice(0, lenQ);
		// This is the fixed part of Q
		// First t bytes of Q are the tweak, next numPad bytes are already zero-valued
		copy(Q, 0, t, tweak);
	
		// Use PQ as a combined storage for P||Q
		// PQ will use the next 16+lenQ bytes of buf
		// Important: PQ is going to be encrypted in place,
		// so P and Q will also remain separate and copied in each iteration
		let PQ = buf.slice(lenQ, lenQ + lenPQ);
	
		// These are re-used in the for loop below
		// variables names prefixed with "num" indicate big integers
		let numA, numB, numC, numRadix, numY, numU, numV, numModU, numModV = BigNumber(0);
		let numABytes = new Uint8Array();
		// TODO: check if BigNumber set it right. All these 'nums' are set to int64.
		// original GO: numRadix.SetInt64(int64(radix))
		try {
			numRadix = BigNumber(radix);
		}
		catch (error) {
			throw error;
		}

		// Y starts at the start of last block of PQ, requires lenY bytes
		// R is part of Y, Overlaps part of PQ
		const Y = buf.slice(lenQ + lenPQ - blockSize, buf.length);
	
		// R starts at Y, requires blockSize bytes, which uses the last block of PQ
		let R = Y.slice(0, blockSize);
		
		// This will only be needed if maxJ > 1, for the inner for loop
		// xored uses the blocks after R in Y, if any
		const xored = Y.slice(blockSize, Y.length);
		
		// Pre-calculate the modulus since it's only one of 2 values,
		// depending on whether i is even or odd
		try {
			numU = BigNumber(u);
			numV = BigNumber(v);
		}
		catch (error) {
			throw error;
		}
		
		// PS: in Go big.Exp returns 1 if power is less than 0 while this BigNumber rounds the result
		// thus this if statement below is added.
		if (numU.isLessThan(0)) {
			numModU = BigNumber(1);
		} else {
			try {
				numModU = numRadix.pow(numU);
			}
			catch (error) {
				throw error;
			}
		}

		if (numU.isLessThan(0)) {
			numModV = BigNumber(1);
		} else {
			try {
				numModV = numRadix.pow(numV);
			}
			catch (error) {
				throw error;
			}
		}
		
		// Bootstrap for 1st round
	
		try {
			numA = BigNumber(A, radix);
		}
		catch (error) {
			throw ErrStringNotInRadix;
		}

		try {
			numB = BigNumber(B, radix);
		}
		catch (error) {
			throw ErrStringNotInRadix;
		}
	
		// Main Feistel Round, 10 times
	
		for (let i = numRounds - 1; i >= 0; i--) {
			// Calculate the dynamic parts of Q
			Q[t+numPad] = toUint8(i);
	
			// TODO: change Bytes
			numABytes = numA.Bytes();
	
			// Zero out the rest of Q
			// When the second half of X is all 0s, numB is 0, so numBytes is an empty slice
			// So, zero out the rest of Q instead of just the middle bytes, which covers the numB=0 case
			// See https://github.com/capitalone/fpe/issues/10
			for (let j = t + numPad + 1; j < lenQ; j++) {
				Q[j] = 0x00;
			}
	
			// B must only take up the last b bytes
			copy(Q, lenQ - numABytes.length, Q.length, numABytes);
	
			// PQ = P||Q
			// Since prf/ciph will operate in place, P and Q have to be copied into PQ,
			// for each iteration to reset the contents
			copy(PQ, 0, blockSize, P);
			copy(PQ, blockSize, PQ.length, Q);
	
			// R is guaranteed to be of length 16
			try {
				R = this.prf(PQ);
			} 
			catch (error) {
				throw error;
			}
	
			// Step 6iii
			for (let j = 1; j < maxJ; j++) {
				// offset is used to calculate which xored block to use in this iteration
				const offset = (j - 1) * blockSize;
	
				// Since xorBytes operates in place, xored needs to be cleared
				// Only need to clear the first 8 bytes since j will be put in for next 8
				for (let x = 0; x < halfBlockSize; x++) {
					xored[offset + x] = 0x00;
				}
				// TODO: change to JS
				binary.BigEndian.PutUint64(xored[offset+halfBlockSize:offset+blockSize], uint64(j));
	
				// XOR R and j in place
				// R, xored are always 16 bytes
				for (let x = 0; x < blockSize; x++) {
					xored[offset+x] = R[x] ^ xored[offset+x];
				}
	
				// AES encrypt the current xored block
				try {
					this.ciph(xored.slice(offset, offset + blockSize));
				}
				catch (error) {
					throw error;
				}
			}

			// TODO: change setBytes
			numY.SetBytes(Y.slice(0, d));

			numC = numB.minus(numY);
	
			if (i % 2 == 0) {
				numC = numC.mod(numModU);
			} else {
				numC = numC.mod(numModV);
			}
	
			// big.Ints use pointers behind the scenes so when numB gets updated,
			// numA will transparently get updated to it. Hence, set the bytes explicitly
			// TODO: check this "numA will transparently get updated to it" thing in JS
			
			// TODO: SetBytes interprets buf as the bytes of a big-endian unsigned integer, sets z to that value, and returns z.
			// TODO: change this 'SetBytes' to JS
			numB.SetBytes(numABytes);
			numA = numC;
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
		if (input.length % blockSize !== 0) {
			throw new Error('length of ciph input must be multiple of 16');
		}
		// TODO: change code below
		this.cbcEncryptor.CryptBlocks(input, input);
		// Reset IV to 0
		// TODO: change code below
		this.cbcEncryptor.(cbcMode).SetIV(ivZero);
	
		return input;
	
	}
	
	// PRF as defined in the NIST spec is actually just AES-CBC-MAC, which is the last block of an AES-CBC encrypted ciphertext. Utilize the ciph function for the AES-CBC.
	// PRF always outputs 16 bytes (one block)
	prf(input) {
		try {
			const cipher = this.ciph(input);
			return cipher.slice(cipher.length - blockSize, cipher.length);
		}
		catch (error) {
			throw error;
		}
	}
}
