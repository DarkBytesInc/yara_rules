rule Win_Trojan_Grab_1
{
strings:
	$a0 = { d314bfffbf703b1034fc710700307175b66e17576974616d2000086a6573746507364772613676 }

condition:
	$a0
}

        
