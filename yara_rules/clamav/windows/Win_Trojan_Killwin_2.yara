rule Win_Trojan_Killwin_2
{
strings:
	$a0 = { 6364202557696e446972255c53797374656d5c200d0a64656c74726565202f79202a2e646c6c }

condition:
	$a0
}

        
