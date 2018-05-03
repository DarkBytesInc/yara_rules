rule Win_Worm_Koobface_23
{
strings:
	$a0 = { 31646e733231303130392e636f6d }
	$a1 = { 633a5c77692573667425646634342e646174 }

condition:
	$a0 and $a1
}

        
