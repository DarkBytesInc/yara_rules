rule Win_Trojan_Stoned_68
{
strings:
	$a0 = { cf00c007e999000039a200f01201809f007c00001e5080fc02721780fc04731280fa80740d31c08ed8a03f04a80190 }

condition:
	$a0
}

        
