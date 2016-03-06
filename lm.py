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
### Windows LM HASH ALGORITHM 
##########################################################################################

import pyDes


##########################################################################################
def __getKey (part):
	"""From a splitted part of the password, return the DES key will be used to calculate each part of LM hash."""

	k = list(['']*8)
	
	for i in range(8):
		# Add a bit for each 7 bits
		if not i:
			k[7-i] = (int (part[-(1+i)],16) << 1) & 0xff
		else:
			k[7-i] = (( int (part[-(1+i)],16) << (i+1) ) | ( int (part[-(i)],16) >> (8-i) << 1 )) & 0xff
		
		# Calculate the parity of the 7-bits and modify the parity bit when needed (not required, so it's commented)
		#acum = 0x00
		#for j in range(7):
			#acum = acum ^ ( k[7-i]<<j & 0x80 )

		#if not acum:
			#k[7-i] = k[7-i]+1
	
	return ''.join( [ chr(x) for x in k ] )


##########################################################################################
def hexdigest (password):
	"""This method returns the LM hash of a password in a hexadecimal string.
	
	@param password The password to calculate the LM hash.
	@return A hexadecimal string with the LM value"""
	
	return digest(password).encode('hex')


##########################################################################################
def digest (password):
	"""This method returns the LM hash of a password in a binary string.
	
	@param password The password to calculate the LM hash.
	@return A binary string with the LM value"""
	
	# Get the PASSWORD (uppercase)
	upperPass = password.upper()
	
	# Get a list with each character of upperPass in hex format
	mPass = map(hex,map(ord,upperPass))
	
	# Pad with NULLs
	mPass.extend (['0x00']*(14-len(mPass)))
	
	# Split in 2 7-bytes parts and get the 2 related keys
	key1 = __getKey ( ['0x00'] + mPass[:7] )
	key2 = __getKey ( ['0x00'] + mPass[7:14] )
	
	# Get the LM hash
	BASESTRING = 'KGS!@#$%'
	
	des = pyDes.des ( key1, mode=pyDes.ECB, pad='\x00' )
	lmhash = des.encrypt( BASESTRING )
	
	des = pyDes.des ( key2, mode=pyDes.ECB, pad='\x00' )
	lmhash += des.encrypt( BASESTRING )
	
	# Return the LM hash
	return lmhash


