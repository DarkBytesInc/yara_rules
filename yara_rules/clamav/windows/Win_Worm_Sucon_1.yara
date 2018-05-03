rule Win_Worm_Sucon_1
{
strings:
	$a0 = { 0a4b696c6c2077696e646972202b20225c726567656469742e65786522 }

condition:
	$a0
}

        
