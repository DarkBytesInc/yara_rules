rule Win_Spyware_Banker_6260
{
strings:
	$a0 = { 0e09681131d98b28bc7f0d1101bb3e73ae7ff6008a27c2e4e58bacc62cef8da7293526629a5adda65f776257ae49e37ab4c722d17c8dc4915939c4aebb94c9d7402bf491eed2e1a7bee654dbe717db0e21eefea0cd }

condition:
	$a0
}

        
