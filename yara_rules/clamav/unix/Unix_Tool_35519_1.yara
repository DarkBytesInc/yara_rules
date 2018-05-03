rule Unix_Tool_35519_1
{
strings:
	$a0 = { 31c050686f6c686f68686f6c68682f686f6c682f746d7089e3b028cd8031c089c3b001cd80 }

condition:
	$a0
}

        
