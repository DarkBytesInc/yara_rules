rule Win_Adware_Admoke_6
{
strings:
	$a0 = { 6c6c2e7070726963682e636f6d2e747874000000ffffffff1b000000b3ccd0f2d4b1bcb6b1f0b5e7c4d42cb2bbd7f6b2d9d7f74578697400ffffffff14000000687474703a2f2f7777772e736f676f75 }

condition:
	$a0
}

        
