rule Win_Worm_P2Load_1
{
strings:
	$a0 = { 6520227662322e646c6c222e00000000ffffffff21000000687474703a2f2f7777772e7032702d6c6f }

condition:
	$a0
}

        
