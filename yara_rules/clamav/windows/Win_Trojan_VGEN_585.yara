rule Win_Trojan_VGEN_585
{
strings:
	$a0 = { e800008bfc368b2d44448d762a8b5612e80400eb180000b9cc0031140bd27408f7040100740142424646e2eec3b8 }

condition:
	$a0
}

        
