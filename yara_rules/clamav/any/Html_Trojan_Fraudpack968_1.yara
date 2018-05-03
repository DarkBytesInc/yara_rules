rule Html_Trojan_Fraudpack968_1
{
strings:
	$a0 = { 6a??ff15082040002bca2bca2bca2bca2bca2bca2bca2bca2bca2bca2bca2bca }

condition:
	$a0
}

        
