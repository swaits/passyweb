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
var passy;
passy = function(text, secret) {
  var encode, hex2passy, symtab;
  symtab = "ABCDEFGHabcdefgh23456789#$%*+=@?";
  hex2passy = function(x) {
    return symtab[parseInt(x, 16) % symtab.length];
  };
  encode = function(str) {
    var i;
    return ((function() {
      var _ref, _results;
      _results = [];
      for (i = 0, _ref = str.length; (0 <= _ref ? i < _ref : i > _ref); i += 2) {
        _results.push(hex2passy(str.substr(i, 2)));
      }
      return _results;
    })()).join("");
  };
  return [encode(SHA1.hmac(secret, text).substr(0, 24)), SHA1.hmac(secret, text).substr(0, 10)];
};


/* This is the source CoffeeScript code:

passy = (text,secret) ->

  # our symbol table for passy
  symtab = "ABCDEFGHabcdefgh23456789#$%*+=@?"

  # convert a hex string to a single passy character
  # * modulo and lookup in symtab string
  hex2passy = (x) -> symtab[parseInt(x,16) % symtab.length]

  # encode a hex string into a passy string
  # 1. split a string into two character strings (octets)
  # 2. encode each two char string (octet) into a single passy char
  # 3. join resulting array of passy chars into a single passy string
  encode = (str) ->
    (hex2passy(str.substr(i,2)) for i in [0...str.length] by 2).join("")

  # return the first 12 characters of the passy string and 10 characters of hmac
  [encode(SHA1.hmac(secret,text).substr(0,24)), SHA1.hmac(secret,text).substr(0,10)]

*/
