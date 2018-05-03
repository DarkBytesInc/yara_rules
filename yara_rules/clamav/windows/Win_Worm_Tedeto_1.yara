rule Win_Worm_Tedeto_1
{
strings:
	$a0 = { 2f74696d657220??202472616e6428[0-4]29202f72756e20696578706c6f726520687474703a2f2f }

condition:
	$a0
}

        
