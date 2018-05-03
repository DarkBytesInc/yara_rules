rule Win_Worm_Koobface_50
{
strings:
	$a0 = { 2f6d7973706163652e6300006d2573636500000079737061 }
	$a1 = { 6625736f6b000000616365626f }

condition:
	$a0 and $a1
}

        
