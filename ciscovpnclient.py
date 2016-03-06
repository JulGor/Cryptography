# -*- coding: iso-8859-1 -*-
import hashlib
import pyDes
from random import sample
from binascii import a2b_hex, b2a_hex

##################################################################################
@staticmethod
def decrypt (data):
	
	# hex2bin
	ct = a2b_hex (data)
	
	# Extract the encrypted password
	enc = ct[40:]
	
	# Extract the IV
	iv = ct[:8]
	
	# Construct the key
	ht = ct[:19] + chr(ord(ct[19])+1)
	key = hashlib.sha1(ht).digest()
	
	ht = ht[:19] + chr(ord(ht[19])+2)
	key += hashlib.sha1(ht).digest()[:4]
	
	# Decrypt the password
	des = pyDes.triple_des (key, pyDes.CBC, iv)#, padmode = pyDes.PAD_PKCS5)
	pwd = des.decrypt (enc)
	
	print ord(pwd[-1])
	
	return pwd #[:-1]

##################################################################################
@staticmethod
def encrypt (string):
	
	# The first 20 bytes are random
	charset = '0123456789abcde'*6
	data = "".join( sample ( list(charset), 80) )
	
	# hex2bin
	ct = a2b_hex (data)
	
	# Extract the IV
	iv = ct[0:8]
	
	# Construct the key
	ht = ct[0:19] + chr(ord(ct[19])+1)
	key = hashlib.sha1(ht).digest()
	
	ht = ht[0:19] + chr(ord(ht[19])+2)
	key += hashlib.sha1(ht).digest()[0:4]
	
	# Encrypt the string 
	des = pyDes.triple_des (key, pyDes.CBC, iv, pad = '\01') #, padmode = pyDes.PAD_PKCS5)
	encpassword = des.encrypt (string)
	
	#asciipassword = b2a_hex(encpassword)
	#print "** Enc Password: >%s<" % asciipassword
	
	#ct  = a2b_hex (data)
	#iv = ct[0:8]
	#ht = ct[0:19] + chr(ord(ct[19])+1)
	#key = hashlib.sha1(ht).digest()
	#ht = ht[0:19] + chr(ord(ht[19])+2)
	#key += hashlib.sha1(ht).digest()[0:4]
	
	#des = pyDes.triple_des (key, pyDes.CBC, iv)
	#pwd = des.decrypt (encpassword)
	#print "** Descifrada: >%s<" % pwd
	#print ord(pwd[-1])
	
	# bin2hex
	data = b2a_hex(ct[:40]) + b2a_hex(encpassword)
	
	return data


if __name__ == "__main__":
	
	import sys
	from random import seed
	seed ()
	
	#pwd = decrypt("071b15ca6e98f1d339d9b25be350daab9a1c5e0b6499850b610e631fcbfb79a91e4e8fdff813e064dcecfe6a5233998dc58c9db8099435de")
	pwd = decrypt(sys.argv[1])
	print pwd 
	
	print "****************"

	enc = encrypt('hola mundo')
	print enc
	
	print "****************"
	pwd = decrypt(enc)
	print pwd
	print "****************"

