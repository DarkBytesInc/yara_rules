rule Win_Trojan_CVE_2012_0773_2
{
strings:
	$a0 = { 464c560105000000090000000017??????00000000000000 }

condition:
	$a0
}

        
