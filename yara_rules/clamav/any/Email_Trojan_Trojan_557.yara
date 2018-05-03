rule Email_Trojan_Trojan_557
{
strings:
	$a0 = { 53686f636b696e6720766964656f21204361746368206d6f6d656e7473 }

condition:
	$a0
}

        
