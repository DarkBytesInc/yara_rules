rule Win_Trojan_W_265
{
strings:
	$a0 = { 4401000050b84d21400050e8440100008bf8b02e3a07740347ebf9be1b224000b905000000f3a4 }

condition:
	$a0
}

        
