rule Win_Trojan_VB_1654
{
strings:
	$a0 = { 74657262616c616e63650050000000b12fa8237342f54190213ab17a913a960000 }

condition:
	$a0
}

        
