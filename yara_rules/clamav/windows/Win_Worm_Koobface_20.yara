rule Win_Worm_Koobface_20
{
strings:
	$a0 = { 633a5c77696e646f77735c66343966346439392e646174 }
	$a1 = { 6132323039323030382e636f6d }
	$a2 = { 2f66622f6c6f67732e706870 }

condition:
	$a0 and $a1 and $a2
}

        
