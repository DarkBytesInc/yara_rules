rule Win_Trojan_Soul_1
{
strings:
	$a0 = { a0e1a8a1ae20537465616c748092682067726f75702e01200a0901530b6c0873052e636f0000 }

condition:
	$a0
}

        
