rule Win_Trojan_Encriyoko_1
{
strings:
	$a0 = { 687474703a2f2f736f75726365736c616e672e69776562732e77732f646f776e732f7a64782e74677a }

condition:
	$a0
}

        
