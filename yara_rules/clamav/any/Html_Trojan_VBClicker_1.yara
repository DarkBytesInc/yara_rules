rule Html_Trojan_VBClicker_1
{
strings:
	$a0 = { 68c4134000e8eeffffff0000000000003000000048 }
	$a1 = { 69006600720061006d0065 }
	$a2 = { 49006e007300740061006c006c002e00740078 }

condition:
	$a0 and $a1 and $a2
}

        
