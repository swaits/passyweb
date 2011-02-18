/*
 * passy.js - implementation of passy algorithm in javascript, by Stephen Waits
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
	 * + substitutes one of 32 symbols for every two hex digits (octet)
	 *
	 */
	var passify = function(hexstr)
	{
		var 
			// lookup table to convert a single character to a symbol
			symtab = [
				"A", "B", "C", "D", "E", "F", "G", "H",
				"a", "b", "c", "d", "e", "f", "g", "h",
				"2", "3", "4", "5", "6", "7", "8", "9",
				"#", "$", "%", "*", "+", "=", "@", "?"
			],

			// lookup table to convert a single hex character to its decimal equivalent
			hex2int = {
				"0":0, "1":1,  "2":2,  "3":3,  "4":4,  "5":5,  "6":6,  "7":7,
				"8":8, "9":9, "a":10, "b":11, "c":12, "d":13, "e":14, "f":15
			},
			
			// our result
			result = "",

			// misc
			i, octet;

		// convert each octet in the hex string to one of our symbols
		for(i=0;i<hexstr.length/2;++i)
		{
			octet = hex2int[hexstr[i*2]]*16 + hex2int[hexstr[i*2+1]];
			result = result + symtab[ octet % symtab.length ];	
		}

		// finished
		return result;
	};

	// get hmac
	var hmac = (SHA1.hmac(secret,text)).toLowerCase();

	// split into four 10 character strings and "passify", and return the array
	// include the unpassified versions afterward
	return [
		passify(hmac.slice( 0,24)),
		hmac.slice( 0,10) ];
};
