rule Win_Worm_Stration_523
{
strings:
	$a0 = { 5c0000002e65786500000000674048415c434f5a4741402e00000000a78296938697d2 }

condition:
	$a0
}

        
