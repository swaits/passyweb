function char_code_to_bytes(code)
{
	var result = [];
	do
	{
		result.push(code & 0xff);
		code = code >> 8;
	} while (code);
	return result.reverse();
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

function sha1(text)
{
	// get text into byte array
	var message = str_to_bytes(text);
	var message_size_in_bits = message.length * 8;

	// Initialize variables:
	var h0 = 0x67452301;
	var h1 = 0xEFCDAB89;
	var h2 = 0x98BADCFE;
	var h3 = 0x10325476;
	var h4 = 0xC3D2E1F0;

	// Pre-processing:

	// append the bit '1' to the message
	message.push(0x80); 

	// append (0 <= k < 512) bits '0', so that the resulting message length (in bits) is congruent to 448 = -64 (mod 512)
	while ((message.length + 8) % 64) 
		message.push(0);

	// append length of message (before pre-processing), in bits, as 64-bit big-endian integer
	message = message.concat(num_to_big_endian_64(message_size_in_bits));

	// Process the message in successive 512-bit chunks:

	// break message into 512-bit chunks
	for (var i_chunk = 0; i_chunk < (message.length/8); i_chunk++)
	{
		// break chunk into sixteen 32-bit big-endian words w[i], 0 <= i <= 15
		var w = bytes_to_big_endian_32(message);
	};
	
	return message;
}
