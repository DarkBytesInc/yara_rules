rule Win_Trojan_MARKJ983_1
{
strings:
	$a0 = { 0400c0b800d60000bedf0400c0e842010000813e504500000f85fd000000813d230500c054 }

condition:
	$a0
}

        
