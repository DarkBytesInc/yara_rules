rule Win_Trojan_Spambot_140
{
strings:
	$a0 = { ca01ffffffef66ce65bf909857ed2759467357b1bb052b7ff25e84f55db8586d5c0368ff0ffe07479e57bc427f502973e13babf6006ad891b7119407ffefff56982ae31725e064b463b015ad72216bb0f0b19e9369faffffffff51bbaabeaeaaeabdc3df8cb2f047fa7ecd626e30 }

condition:
	$a0
}

        
