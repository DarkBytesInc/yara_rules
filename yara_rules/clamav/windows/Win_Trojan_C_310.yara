rule Win_Trojan_C_310
{
strings:
	$a0 = { a19010400053a348c04100a19410400033db53a344c04100ff158c10 }
	$a1 = { 53007000790077006100720065 }

condition:
	$a0 and $a1
}

        
