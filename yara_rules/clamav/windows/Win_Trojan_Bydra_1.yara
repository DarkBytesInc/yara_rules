rule Win_Trojan_Bydra_1
{
strings:
	$a0 = { e55dc30042792044726163686500000042495453000000006265697a6875 }

condition:
	$a0
}

        
