rule Win_Worm_Koobface_44
{
strings:
	$a0 = { 4c6f000065436f6f6b0000006965 }
	$a1 = { 5477690074746572 }
	$a2 = { 4641000063450000426f4f002f }
	$a3 = { 4700450054000000504f5354 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
