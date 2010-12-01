/*jslint onevar: true, undef: true, nomen: true, regexp: true, newcap: true, immed: true, strict: true */

SHA1 = (function() // SHA1 "namespace"
{
	"use strict";

	var hextab = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"];

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

	function str_to_bytes(str)
	{
		var result = [], i, len = str.length;
		for (i=0; i<len; i++)
		{
			result = result.concat( char_code_to_bytes(str.charCodeAt(i)) );
		}
		return result;
	}

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

	function bytes_to_big_endian_32(array)
	{
		var result = [], i, len = array.length;
		for (i=0; i<len; i+=4)
		{
			result.push((array[i] << 24) | (array[i+1] << 16) | (array[i+2] <<  8) | array[i+3]);
		}
		return result;
	}

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

	function sha1_string(str)
	{
		// get text into byte array, hash, convert to hex string
		return bytes_to_hex(sha1(str_to_bytes(str)));
	}

	function sha1_verify()
	{
		return Boolean(
				(sha1_string("The quick brown fox jumps over the lazy dog") == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") &&
				(sha1_string("")                                            == "da39a3ee5e6b4b0d3255bfef95601890afd80709")
				);
	}

	function sha1_profile()
	{
		var data = [1,2,3,4,5,6], i;
		for (i=0; i<5000; i++)
		{
			sha1(data);
		}
	}

	function hmac_sha1(key_str, message_str)
	{
		var
			// convert key & message to byte arrays
			key     = str_to_bytes(key_str),
			message = str_to_bytes(message_str),

			// our pads
			opad = new Array(20),
			ipad = new Array(20),

			// misc
			i;

		// setup key
		if (key.length > 20)
		{
			key = sha1(key); // keys longer than blocksize are shortened
		}
		while (key.length < 20)
		{
			key.push(0);
		}

		for (i=0; i<20; i++)
		{
			opad[i] = 0x5c ^ key[i];
			ipad[i] = 0x36 ^ key[i];
		}

		return bytes_to_hex(sha1(opad.concat(sha1(ipad.concat(message)))));
	}

	function hmac_verify()
	{
		var h = hmac_sha1('Jefe','what do ya want for nothing?');
		return Boolean(h == 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79');
		//return Boolean(hmac_sha1("a","b") == "6657855686823986c874362731139752014cb60b");
	}

	// our exports
	return {
		hash:sha1_string,
		hmac:hmac_sha1,
		test:hmac_verify
	};

}()); // SHA1 "namespace"
