rule Win_Trojan_Agent_35183
{
strings:
	$a0 = { 9c3cee473ce0e8000000005b8bc34a4981eb401001008bccf5f85347f5f981c03e000000424185c56800000000 }

condition:
	$a0
}

        
