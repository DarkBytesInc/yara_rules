rule Email_Trojan_Ecard_7
{
strings:
	$a0 = { 617465642061206772656574696e67206361726420666f7220796f75 }
	$a1 = { 687474703a2f2f37 }

condition:
	$a0 and $a1
}

        
