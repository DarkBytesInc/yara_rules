rule Win_Trojan_Crypted_31
{
strings:
	$a0 = { 909090909060 }

condition:
	$a0
}

        
