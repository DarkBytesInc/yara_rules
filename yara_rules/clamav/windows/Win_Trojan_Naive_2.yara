rule Win_Trojan_Naive_2
{
strings:
	$a0 = { 0e1f33c933d2b4f1cd2181f93412750981fa78567503eb63908cc0488ec026803e00005a75554026832e03006a9090 }

condition:
	$a0
}

        
