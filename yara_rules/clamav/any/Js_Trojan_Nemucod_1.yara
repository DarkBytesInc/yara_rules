rule Js_Trojan_Nemucod_1
{
strings:
	$a0 = { 3d2022736c656570223b7768696c6520 }
	$a1 = { 29207b777363726970745b??????5d28 }

condition:
	$a0 and $a1
}

        
