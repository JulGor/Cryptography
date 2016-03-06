##########################################################################################
### LICENSE
##########################################################################################
#
# This code is part of findmyhash v 2.0
#
# This code is under GPL v3 License (http://www.gnu.org/licenses/gpl-3.0.html).
#
# Developed by JulGor ( http://laxmarcaellugar.blogspot.com/ )
# Mail: julgoor # gmail ! com
# twitter: @laXmarcaellugar
#


##########################################################################################
### MySQL HASH ALGORITHMS
###
###   - 'password' function is equivalent to MySQL PASSWORD function which calculates
###     the hash of a password in MySQL version 4.1+
###
###   - 'old_password' function is equivalent to MySQL OLD_PASSWORD function which 
###     calculates the hash of a password in MySQL prior 4.0
###
##########################################################################################

from mhash import MHASH, MHASH_SHA1


##################################################################################
### MySQL 4.1+ hash functions
##################################################################################

##################################################################################
def digest_mySQL41plus (string):
	"""This method implements the hash algorithm used in MySQL since version 4.1.1.
	The returned value DO NOT INCLUDE the initial * of the hash.
	
	@param string The string whose hash is going to be calculated.
	@return The binary hash of the input string.
	"""
	
	return MHASH ( MHASH_SHA1, MHASH(MHASH_SHA1, string).digest() ).digest()


##################################################################################
def hexdigest_mySQL41plus (string):
	"""This method implements the hash algorithm used in MySQL since version 4.1.1.
	
	@param string The string whose hash is going to be calculated.
	@return The hexadecimal hash of the input string.
	"""
	
	return '*' + MHASH ( MHASH_SHA1, MHASH(MHASH_SHA1, string).digest() ).hexdigest()



##################################################################################
def password (string):
	"""This method calls the hexdigest_mySQL41plus function. It is implemented
	to respect the original MySQL name of the function.
	
	@param string The string whose hash is going to be calculated.
	@return The hexadecimal hash of the input string.
	"""
	
	return hexdigest_mySQL41plus (string)



##################################################################################
### MySQL prior 4.1 hash functions
##################################################################################


##################################################################################
def hexdigest_mySQL41prior (string):
	"""This method implements the hash algorithm used in MySQL until version 4.0.
	
	@param string The string whose hash is going to be calculated.
	@return The hexadecimal hash of the input string.
	"""
	
	# Initial variables
	nr = 1345345333
	add = 7
	nr2 = 0x12345671
	tmp = None
	
	# Algorithm
	for i in range( len(string) ):
		
		if string[i] in [' ', '\t']:
			continue
		
		tmp = ord(string[i])
		
		nr ^= (((nr & 63) + add) * tmp) + ((nr << 8) & 0xFFFFFFFF)
		nr2 += ((nr2 << 8) & 0xFFFFFFFF) ^ nr
		add += tmp
	
	# Output
	out_a = nr & ((1 << 31) - 1)
	out_b = nr2 & ((1 << 31) - 1)
	
	
	return '%08x%08x' % (out_a , out_b )


##################################################################################
def digest_mySQL41prior (string):
	"""This method implements the hash algorithm used in MySQL until version 4.0.
	
	@param string The string whose hash is going to be calculated.
	@return The binary hash of the input string.
	"""
	
	return hexdigest_mySQL41prior(string).decode('hex')



##################################################################################
def old_password (string):
	"""This method calls the hexdigest_mySQL41prior function. It is implemented
	to respect the original MySQL name of the function.
	
	@param string The string whose hash is going to be calculated.
	@return The hexadecimal hash of the input string.
	"""
	
	return hexdigest_mySQL41prior (string)

