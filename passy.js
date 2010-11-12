/*
 * Given a "text" (i.e. "amazon.com") and a "secret" (i.e. "mypassword") return an
 * array of four Passy'fied passwords.
 */
var passy = function(text,secret)
{
	/*
	 * function to make a password out of a hexadecimal string "0123456789abcdef".
	 *
	 * + substitutes symbols for every other digit [0-9]
	 * + capitalize every other alpha [a-f]
	 *
	 */
	var passify = function(hexstr)
	{
		// lookup table to convert a single character to a symbol
		var symtab = { "1":"!", "2":"@", "3":"#", "4":"$", "5":"%", "6":"^", "7":"&", "8":"*", "9":"(", "0":")" };

		// convert every other numerical character to a symbol
		var odd = true;
		for(i=0;i<hexstr.length;++i)
		{
			// is this a digit-character?
			if ( /[0-9]/.test(hexstr[i]) )
			{
				if ( odd )
				{
					// substitute symbol for odd digit-characters, leave even digit-characters alone!
					hexstr = hexstr.slice(0,i) + symtab[hexstr[i]] + hexstr.slice(i+1,hexstr.length);
				}

				// flip odd toggle
				odd = !odd;
			}
		}

		// alternate uppercase/lowercase for alpha characters
		odd = true;
		for(i=0;i<hexstr.length;++i)
		{
			// is this an alpha-character?
			if ( /[a-f]/i.test(hexstr[i]) )
			{
				// set odd alpha-characters to uppercase, and even alpha-characters to lowercase
				hexstr = 
					hexstr.slice(0,i) + 
					( odd ? hexstr[i].toUpperCase() : hexstr[i].toLowerCase()) + 
					hexstr.slice(i+1,hexstr.length);

				// flip odd toggle
				odd = !odd;
			}
		}

		// finished
		return hexstr;
	}

	// get hmac
	var hmac = new jsSHA(text.toLowerCase(), "ASCII").getHMAC(secret, "ASCII", "HEX");

	// split into four 10 character strings and "passify", and return the array
	return [
		passify(hmac.slice( 0,10)),
		passify(hmac.slice(10,20)),
		passify(hmac.slice(20,30)),
		passify(hmac.slice(30,40))];
}
