rule Win_Trojan_VB_1037
{
strings:
	$a0 = { 254e415448454d1463737963454f60663b2c3f742d }
	$a1 = { 3d363f302732234655434b1a1b16120f3b2a3f5448454d35 }

condition:
	$a0 and $a1
}

        
