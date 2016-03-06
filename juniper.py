# $Id: juniper.py 2012/03/04
#
#  Copyright (C) 2012   Julio Gomez Ortega (julgoor # gmail ! com)
#  Licensed to PSF under a Contributor Agreement.
#
#  Based on Kevin Brintnall's Crypt::Juniper Perl implementation
#  ( http://search.cpan.org/dist/Crypt-Juniper/lib/Crypt/Juniper.pm )
#

from random import seed, randint
from re import match


__doc__ = """Encrypt/decrypt Juniper $9$ secrets

encrypt (original_string) - Encrypt the string to a Juniper $9$ secrets.

decrypt (encrypted_string, salt=0) - Decrypt the $9$ secret, returning the original string.
				     If no salt is chosen, a random one is created.

Some examples:

	>>> import juniper
	>>> juniper.encrypt ('test')
	'$9$ZdGkPF39pOR/C'
	>>> juniper.decrypt ('$9$ZdGkPF39pOR/C')
	'test'
	
NOTE: encrypt function has a random initialization, so previous example can return
a different value in each execution.

"""

################################################################################
## GLOBAL CONSTANTS

__MAGIC = "$9$"

__ENCODING = [
	[ 1,  4, 32 ],
	[ 1, 16, 32 ],
	[ 1,  8, 32 ],
	[ 1, 64     ],
	[ 1, 32     ],
	[ 1, 4, 16, 128 ],
	[ 1, 32, 64 ]
	]

################################################################################
## Letter families

__FAMILY = [ "QzF3n6/9CAtpu0O", 
	   "B1IREhcSyrleKvMW8LXx", 
	   "7N-dVbwsY2g4oaJZGUDj", 
	   "iHkq.mPf5T" 
	 ]

__EXTRA = {}
for __fam in range (len(__FAMILY)):
	for __c in __FAMILY[__fam]:
		__EXTRA[__c] = 3-__fam


################################################################################
## Forward and reverse dictionaries

__NUM_ALPHA = list(''.join(__FAMILY))

__ALPHA_NUM = {}
for __x in range(len(__NUM_ALPHA)):
	__ALPHA_NUM[__NUM_ALPHA[__x]] = __x



################################################################################
def __check (crypt):
	"""Check if the input string is a valid Juniper crypt string."""
	
	regexp = '\$9\$[QzF3n6/9CAtpu0OB1IREhcSyrleKvMW8LXx7N\-dVbwsY2g4oaJZGUDjiHkq\.mPf5T]{3,}$'
	return match ( regexp, crypt )


################################################################################
def __nibble (cref, num):
	"""Divide cref string into 2 parts: first num characters and the rest.
	It returns a tuple with the 2 parts."""
	
	if num > len(cref):
		raise ValueError, "Ran out of characters: hit '%d', expecting %d chars" % (num, len(cref))
	
	nib = cref[:num]
	cref = cref[num:]
	
	return (nib, cref)


################################################################################
def __randc (cnt):
	"""Return a random number of characters from the alphabet."""
	
	r = ''
	if cnt <= 0:
		return r
	
	while cnt > 0:
		r = r + __NUM_ALPHA[randint(0, len(__NUM_ALPHA)-1)]
		cnt = cnt-1
	
	return r


################################################################################
def __gap (c1, c2):
	"""Calculate the distance between two characters."""
	return ( __ALPHA_NUM[c2] - __ALPHA_NUM[c1] ) % len(__NUM_ALPHA)-1

################################################################################
def __gap_decode (gaps, dec):
	"""Given a series of gaps and moduli, calculate the resulting plaintext."""
	
	if len(gaps) != len(dec):
		raise ValueError, "Nibble and decode size not the same!"
	
	num = 0;
	for i in range(len(gaps)):
		num = num + gaps[i] * dec[i]
	
	return chr ( num % 256 );


################################################################################
def __gap_encode (pc, prev, enc):
	"""Encode a plain-text character with a series of gaps,
	according to the current encoder."""
	
	oord = ord(pc[0])
	
	crypt = ''
	gaps = []
	
	lenc = list(enc)
	lenc.reverse()
	for mod in lenc:
		gaps.insert(0, int(oord/mod))
		oord = oord % mod
	
	for gap in gaps:
		gap = gap + __ALPHA_NUM[prev] + 1
		c = __NUM_ALPHA[ gap % len(__NUM_ALPHA) ]
		prev = c
		crypt = crypt + c
	
	return crypt



################################################################################

def decrypt (crypt):
	"""Decrypt the string 'crypt', returning the corresponding plain-text.
	Input string must be of the format "$9$blahblah". 
	
	This function will raise an ValueError exception if there is any processing errors."""
	
	if not crypt:
		return ""
	
	if not __check (crypt):
		raise ValueError, "Invalid Juniper crypt string!: %s" % crypt
	
	chars = crypt[3:] 
	
	(first, chars) = __nibble(chars, 1);
	(rest, chars) = __nibble(chars, __EXTRA[first])
	
	prev = first
	decrypt = ''
	
	while chars:
		
		decode = __ENCODING[ len(decrypt) % len(__ENCODING) ]
		
		length = len(decode)
		(nibble, chars) = __nibble(chars, length)
		
		gaps = []
		for c in nibble:
			g = __gap (prev, c)
			prev = c
			gaps.append (g)
		
		decrypt = decrypt + __gap_decode(gaps, decode)
		
	return decrypt;

################################################################################

def encrypt (plain, salt=0):
	"""Encrypt the plain text, returning a result suitable for inclusion in a Juniper configuration.
	If no salt is chosen, a random one is created."""

	seed()
	
	if not salt:
		salt = __randc(1)
	
	rand = __randc(__EXTRA[salt])
	
	pos = 0
	prev = salt
	crypt = __MAGIC + salt + rand
	
	for p in plain:
		encode = __ENCODING[ pos % len(__ENCODING) ]
		crypt = crypt + __gap_encode (p, prev, encode)
		prev = crypt[-1:]
		pos = pos + 1
	
	return crypt






