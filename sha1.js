/*
 * sha1.js - implementation of SHA-1 hash and HMAC algorithms in javascript, by Stephen Waits
 *
 * The MIT License
 * 
 * Copyright (c) 2010 Stephen Waits <steve@waits.net>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*jslint onevar: true, undef: true, nomen: true, regexp: true, newcap: true, immed: true */

var SHA1 = (function() // SHA1 "namespace"
{
	// table for doing number to hex string conversion
	var hextab = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"];

	// convert one character to an array of bytes
	function char_code_to_bytes(code)
	{
		var result = [];
		do
		{
			result.unshift(code & 0xff);
			code >>= 8;
		} while (code);
		return result;
	}

	// convert a string to an array of bytes
	// note: multi-byte characters are included
	function str_to_bytes(str)
	{
		var result = [], i, len = str.length;
		for (i=0; i<len; i++)
		{
			result = result.concat( char_code_to_bytes(str.charCodeAt(i)) );
		}
		return result;
	}

	// take a number and return an array of 8 bytes representing a big-endian int64
	function num_to_big_endian_64(num)
	{
		return [
			(num & 0xff00000000000000) >>> 56,
			(num & 0x00ff000000000000) >>> 48,
			(num & 0x0000ff0000000000) >>> 40,
			(num & 0x000000ff00000000) >>> 32,
			(num & 0x00000000ff000000) >>> 24,
			(num & 0x0000000000ff0000) >>> 16,
			(num & 0x000000000000ff00) >>>  8,
			(num & 0x00000000000000ff)       
			];
	}

	// convert an array of bytes to an array of int32 (big-endian)
	function bytes_to_big_endian_32(array)
	{
		var result = [], i, len = array.length;
		for (i=0; i<len; i+=4)
		{
			result.push((array[i] << 24) | (array[i+1] << 16) | (array[i+2] <<  8) | array[i+3]);
		}
		return result;
	}

	// take an array of bytes and return the hex string
	function bytes_to_hex(x)
	{
		var
			result = "",
			len = x.length,
			i;

		for (i=0; i<len; i++)
		{
			result += (hextab[x[i] >>> 4]) + (hextab[x[i] & 0xf]);
		}
		return result;
	}

	// compute SHA1 hash
	//
	// input is an array of bytes (big-endian order)
	// returns an array of 20 bytes
	function sha1(byte_array)
	{
		var
			// copy array
			message = byte_array.slice(),

			// store message size for later use
			message_size_in_bits = message.length * 8,

			// Initialize variables:
			h0 = 0x67452301,
			h1 = 0xefcdab89,
			h2 = 0x98badcfe,
			h3 = 0x10325476,
			h4 = 0xc3d2e1f0,

			// variables
			a, b, c, d, e, s, temp, w, i, i_chunk;

		// Pre-processing:

		// append the bit '1' to the message
		message.push(0x80); 

		// append (0 <= k < 512) bits '0', so that the resulting message length (in bits) is congruent to 448 = -64 (mod 512)
		while ((message.length + 8) % 64) 
		{
			message.push(0);
		}

		// append length of message (before pre-processing), in bits, as 64-bit big-endian integer
		message = message.concat(num_to_big_endian_64(message_size_in_bits));

		// Process the message in successive 512-bit chunks:

		// break message into 512-bit chunks
		for (i_chunk=0; i_chunk<(message.length/64); i_chunk++)
		{
			// break chunk into sixteen 32-bit big-endian words w[i], 0 <= i <= 15
			w = bytes_to_big_endian_32(message.slice(i_chunk*64,(i_chunk*64)+64));

			// Initialize hash value for this chunk:
			a = h0;
			b = h1;
			c = h2;
			d = h3;
			e = h4;

			// Main loop:
			for (i=0; i<80; i++)
			{
				s = i & 0xf;
				if (i >= 16)
				{
					temp = w[(s + 13) & 0xf] ^ w[(s + 8) & 0xf] ^ w[(s + 2) & 0xf] ^ w[s];
					w[s] = (temp << 1) | (temp >>> 31); // rol(temp,1)
				}
				if (i < 20)
				{
					//     _______rol(a,5)_________ + _________f[i]________ + e + ___k[i]___ + w[s]
					temp = (((a << 5) | (a >>> 27)) + ( d ^ (b & (c ^ d)) ) + e + 0x5a827999 + w[s]) & 0xffffffff;
				}
				else if (i < 40)
				{
					//     _______rol(a,5)_________ + _____f[i]____ + e + ___k[i]___ + w[s]
					temp = (((a << 5) | (a >>> 27)) + ( b ^ c ^ d ) + e + 0x6ed9eba1 + w[s]) & 0xffffffff;
				}
				else if (i < 60)
				{
					//     _______rol(a,5)_________ + ___________f[i]________________ + e + ___k[i]___ + w[s]
					temp = (((a << 5) | (a >>> 27)) + ( (b & c) | (b & d) | (c & d) ) + e + 0x8f1bbcdc + w[s]) & 0xffffffff;
				}
				else
				{
					//     ________rol(a,5)_________ + _____f[i]____ + e + ___k[i]___ + w[s]
					temp = (((a << 5) | (a >>> 27)) + ( b ^ c ^ d ) + e + 0xca62c1d6 + w[s]) & 0xffffffff;
				}

				e = d;
				d = c;
				c = (b << 30) | (b >>> 2); // c = rol(b,30)
				b = a;
				a = temp;
			}

			// Add this chunk's hash to result so far:
			h0 = (h0 + a) & 0xffffffff;
			h1 = (h1 + b) & 0xffffffff;
			h2 = (h2 + c) & 0xffffffff;
			h3 = (h3 + d) & 0xffffffff;
			h4 = (h4 + e) & 0xffffffff;
		}

		// Produce the final hash value (big-endian):
		return [
			(h0 >>> 24) & 0xff,  (h0 >>> 16) & 0xff,  (h0 >>> 8) & 0xff,  h0 & 0xff, 
			(h1 >>> 24) & 0xff,  (h1 >>> 16) & 0xff,  (h1 >>> 8) & 0xff,  h1 & 0xff, 
			(h2 >>> 24) & 0xff,  (h2 >>> 16) & 0xff,  (h2 >>> 8) & 0xff,  h2 & 0xff, 
			(h3 >>> 24) & 0xff,  (h3 >>> 16) & 0xff,  (h3 >>> 8) & 0xff,  h3 & 0xff, 
			(h4 >>> 24) & 0xff,  (h4 >>> 16) & 0xff,  (h4 >>> 8) & 0xff,  h4 & 0xff
			]; // note: returning this as a byte array is quite expensive!
	}

	// compute SHA1
	//
	// input is a string
	// returns a hex string
	function sha1_string(str)
	{
		// get text into byte array, hash, convert to hex string
		return bytes_to_hex(sha1(str_to_bytes(str)));
	}

	// compute HMAC-SHA1
	//
	// key_str and message_str are both strings
	// returns a hex string
	function hmac_sha1(key_str, message_str)
	{
		var
			// convert key & message to byte arrays
			key     = str_to_bytes(key_str),
			message = str_to_bytes(message_str),

			// our pads
			opad = new Array(64),
			ipad = new Array(64),

			// misc
			i;

		// setup key
		if (key.length > 64)
		{
			key = sha1(key); // keys longer than blocksize are shortened
		}
		while (key.length < 64)
		{
			key.push(0);
		}

		// setup pads
		for (i=0; i<64; i++)
		{
			opad[i] = 0x5c ^ key[i];
			ipad[i] = 0x36 ^ key[i];
		}

		// calculate HMAC
		return bytes_to_hex(sha1(opad.concat(sha1(ipad.concat(message)))));
	}


	//
	// verification code
	//
	function byte_string(x,size)
	{
		var a = "", s = String.fromCharCode(x);
		for (var i=0; i<size; i++)
		{
			a += s;
		};
		return a;
	}

	// test HMAC-SHA1 with known test vectors
	function verify()
	{
		// testing HMAC-SHA1 also naturally tests SHA1
		var tests = [
				[ 'Jefe','what do ya want for nothing?', 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79' ],
				[ byte_string(0xb,20),'Hi There','b617318655057264e28bc0b6fb378c8ef146be00' ],
				[ byte_string(0xaa,20),byte_string(0xdd,50), '125d7342b9ac11cd91a39af48aa17b4f63f175d3' ],
				[ byte_string(0xc,20),'Test With Truncation','4c1a03424b55e07fe7f27be1d58bb9324a9a5a04' ],
				[ byte_string(0xaa,80),'Test Using Larger Than Block-Size Key - Hash Key First','aa4ae5e15272d00e95705637ce8a3b55ed402112' ],
				[ byte_string(0xaa,80),'Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data','e8e99d0f45237d786d6bbaa7965c7808bbff1a91' ]
			];

		for (var i = 0; i < tests.length; i++) {
			if (hmac_sha1(tests[i][0],tests[i][1]) != tests[i][2]) { return false; }
		};

		return true;
	}


	//
	// exported symbols
	//
	return {
		hash:sha1_string,
		hmac:hmac_sha1,
		test:verify
	};

}()); // SHA1 "namespace"
