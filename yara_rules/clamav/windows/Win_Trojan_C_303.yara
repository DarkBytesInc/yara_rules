rule Win_Trojan_C_303
{
strings:
	$a0 = { 54656d705c54454d505343524950542e766273 }
	$a1 = { 526170746f722056697275732047656e }

condition:
	$a0 and $a1
}

        
