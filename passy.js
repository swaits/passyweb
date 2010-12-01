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
		var 
			// lookup table to convert a single character to a symbol
			symtab = { "1":"!", "2":"@", "3":"#", "4":"$", "5":"%", "6":"^", "7":"&", "8":"*", "9":"(", "0":")" },

			// misc
			odd = true, i;

		// convert every other numerical character to a symbol
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
	};

	// get hmac
	var hmac = SHA1.hmac(secret,text);

	// split into four 10 character strings and "passify", and return the array
	// include the unpassified versions afterward
	return [
		passify(hmac.slice( 0,10)),
		passify(hmac.slice(10,20)),
		passify(hmac.slice(20,30)),
		passify(hmac.slice(30,40)),
		hmac.slice( 0,10),
		hmac.slice(10,20),
		hmac.slice(20,30),
		hmac.slice(30,40)];
};
