# -*- coding: iso-8859-1 -*-

##########################################################################################
### LICENSE
##########################################################################################
#
# This code is part of findmyhash v 2.0
#
# This code is under GPL v3 License (http://www.gnu.org/licenses/gpl-3.0.html).
#
# Developed by JulGor ( http://laxmarcaellugar.blogspot.com/ )
# Mail: julgoor AT gmail DOT com
# twitter: @laXmarcaellugar
#


##########################################################################################
### CISCO7 CRYPTO ALGORITHM 
##########################################################################################

from random import randint

# Fixed string used in Cisco7 algorithm ( "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncx" )
__CISCO7STRING = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncx"

##########################################################################################
def decrypt (crypt):
	"""From an encrypted string, this method returns the original value.
	
	@param crypt The ciphered string.
	@return The decoded value."""
	
	if len(crypt) < 4:
		return ""
	
	# Extract the offset of the key
	offset = int( crypt[:2], 16 )
	
	# Get the integer value of the encoded password
	intencoded = int (crypt[2:], 16)
	
	# Calculate the key
	key = __CISCO7STRING[offset : offset+len(crypt[2:])/2]
	intkey = int( key.encode('hex'), 16)
	
	# intencoded XOR intkey = int password 
	hexpass = intencoded ^ intkey
	
	# ASCII representation of the password is returned
	return ('%x' % hexpass).decode('hex')



##########################################################################################
def encrypt (password):
	"""From an plaintext string, this method returns the Cisco7 encrypted password.
	
	@param password The original password.
	@return The Cisco7 encrypted password."""
	
	# Select a random offset for the key
	offset = randint(0, 15)
	
	# Get the integer value of the password
	intpassword = int( password.encode('hex'), 16 )
	
	# Calculate the key
	key = __CISCO7STRING[offset : offset+len(password)]
	intkey = int( key.encode('hex'), 16)
	
	# intpassword XOR intkey = int hexencrypted
	hexencrypted = intpassword ^ intkey
	
	# ASCII representation of the ciphertext
	tmp = ('%x' % hexencrypted)
	crypt = ('%02x' % offset) + (len(tmp)%2 and '0'+tmp or tmp)
	
	return crypt
