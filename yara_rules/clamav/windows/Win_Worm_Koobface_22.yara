rule Win_Worm_Koobface_22
{
strings:
	$a0 = { 633a5c77696e646f77735c66343966346439392e646174 }
	$a1 = { 7a7a7a70696e672e636f6d[0-1]2f66622f6c6f67732e706870 }

condition:
	$a0 and $a1
}

        
