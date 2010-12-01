#!/usr/bin/env ruby

require 'digest/sha1'

# helper to make a 'length' long string filled with 'byte'
def byte_string(byte, length)
	([byte]*length).pack('C*')
end

def put_bytes(s)
	s.unpack('C*').each { |x| print sprintf("%02d ",x); }
	puts
end

# hmac algorithm - returns text version of hmac
def hmac(key, data, digest_object, blocksize)
	# if key is too long, hash it
	key = digest_object.digest(key) if key.size > blocksize

	# pad key out to blocksize
	key += byte_string(0,blocksize - key.size) if key.size < blocksize

	# create pads
	ipad = byte_string(0x36,blocksize)
	opad = byte_string(0x5c,blocksize)
	blocksize.times do |i|
		#ipad[i] ^= key[i]
		ipad.setbyte(i,ipad.getbyte(i) ^ key.getbyte(i))
		#opad[i] ^= key[i] }
		opad.setbyte(i,opad.getbyte(i) ^ key.getbyte(i))
	end

	puts "Key:  "
	put_bytes(key)
	puts "data: "
	put_bytes(data)
	puts "ipad: "
	put_bytes(ipad)
	puts "opad: "
	put_bytes(opad)
	puts
	puts "hash(ipad + data)"
	puts digest_object.hexdigest(ipad+data)
	puts
	puts "hash(opad+hash(ipad+data))"
	puts digest_object.hexdigest( opad + digest_object.digest( ipad + data ) )

	# do the HMAC and return
	digest_object.hexdigest( opad + digest_object.digest( ipad + data ) )
end

# hmac-sha1
def hmac_sha1(key, data)
	hmac(key, data, Digest::SHA1, 64)
end

hmac_sha1('Jefe','what do ya want for nothing?');
