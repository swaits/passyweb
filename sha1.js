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
	var result = [];
	for (var i = 0; i < str.length; i++)
	{
		result = result.concat( char_code_to_bytes(str.charCodeAt(i)) );
	};
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
	var result = [];
	for (var i = 0; i < (array.length/4); i++)
	{
		result.push((array[i*4+0] << 24) | (array[i*4+1] << 16) | (array[i*4+2] <<  8) | array[i*4+3]);
	};
	return result;
}

function rol(x,n)
{
	return (x << n) | (x >>> (32 - n));
}

function to_hex(x)
{
	var h = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"];
	
	return String( 
		h[(x & 0xf0000000) >>> 28] + 
		h[(x & 0x0f000000) >>> 24] + 
		h[(x & 0x00f00000) >>> 20] + 
		h[(x & 0x000f0000) >>> 16] + 
		h[(x & 0x0000f000) >>> 12] + 
		h[(x & 0x00000f00) >>>  8] + 
		h[(x & 0x000000f0) >>>  4] + 
		h[(x & 0x0000000f) >>>  0]
		);
}

function sha1(text)
{
	// get text into byte array
	var message              = str_to_bytes(text);
	var message_size_in_bits = message.length * 8;

	// Initialize variables:
	var h0 = 0x67452301;
	var h1 = 0xefcdab89;
	var h2 = 0x98badcfe;
	var h3 = 0x10325476;
	var h4 = 0xc3d2e1f0;

	// Pre-processing:

	// append the bit '1' to the message
	message.push(0x80); 

	// append (0 <= k < 512) bits '0', so that the resulting message length (in bits) is congruent to 448 = -64 (mod 512)
	while ((message.length + 8) % 64) 
	{
		message.push(0);
	};

	// append length of message (before pre-processing), in bits, as 64-bit big-endian integer
	message = message.concat(num_to_big_endian_64(message_size_in_bits));

	// Process the message in successive 512-bit chunks:

	// break message into 512-bit chunks
	for (var i_chunk = 0; i_chunk < (message.length/64); i_chunk++)
	{
		// break chunk into sixteen 32-bit big-endian words w[i], 0 <= i <= 15
		var w = bytes_to_big_endian_32(message.slice(i_chunk*64,(i_chunk*64)+64));

		// Extend the sixteen 32-bit words into eighty 32-bit words:
		for (var i = 16; i < 80; i++)
		{
			w.push(rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1));
		};

		// Initialize hash value for this chunk:
		var a = h0;
		var b = h1;
		var c = h2;
		var d = h3;
		var e = h4;
		var f = 0;
		var k = 0;

		// Main loop:
		for (var i = 0; i < 80; i++)
		{
			if (i < 20)
			{
				f = d ^ (b & (c ^ d));
				k = 0x5a827999;
			}
			else if (i < 40)
			{
				f = b ^ c ^ d;
				k = 0x6ed9eba1;
			}
			else if (i < 60)
			{
				f = (b & c) | (b & d) | (c & d);
				k = 0x8f1bbcdc;
			}
			else
			{
				f = b ^ c ^ d;
				k = 0xca62c1d6;
			}
			
			var temp = (rol(a,5) + f + e + k + w[i]) & 0xffffffff;
			e = d;
			d = c;
			c = rol(b,30);
			b = a;
			a = temp;
		};

		// Add this chunk's hash to result so far:
		h0 = (h0 + a) & 0xffffffff;
		h1 = (h1 + b) & 0xffffffff;
		h2 = (h2 + c) & 0xffffffff;
		h3 = (h3 + d) & 0xffffffff;
		h4 = (h4 + e) & 0xffffffff;
	};

	// Produce the final hash value (big-endian):
	return to_hex(h0) + to_hex(h1) + to_hex(h2) + to_hex(h3) + to_hex(h4);
}

function sha1_verify()
{
	return Boolean(
		(sha1("The quick brown fox jumps over the lazy dog") == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") &&
		(sha1("")                                            == "da39a3ee5e6b4b0d3255bfef95601890afd80709")
		);
}

function sha1_profile()
{
	var text = "blah";
	for (var i = 0; i < 250; i++) {
		text = sha1(text);
	};
}
