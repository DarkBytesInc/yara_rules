rule Win_Trojan_VGEN_56
{
strings:
	$a0 = { e800008bfc368b2d44448d762c908b561490e80400eb180000b9cd0031140bd27408f7040100740142424646e2 }

condition:
	$a0
}

        
