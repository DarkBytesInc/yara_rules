rule Win_Trojan_VB_73705
{
strings:
	$a0 = { 737373737975363736380d0a00121c0017ffff03010200000409004c69 }

condition:
	$a0
}

        
