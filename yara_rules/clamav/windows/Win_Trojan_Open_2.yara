rule Win_Trojan_Open_2
{
strings:
	$a0 = { 2e73040326c745150000b440b90300ba7204e8a1005872a026894515b440b9200633d2e89000e8 }

condition:
	$a0
}

        
