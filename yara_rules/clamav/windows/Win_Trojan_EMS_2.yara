rule Win_Trojan_EMS_2
{
strings:
	$a0 = { 8b1e010181c30301e80a0089f78d7703a4a561ffe65356061e53531eb824008ed8813e00009c2e1f74778d7706b8 }

condition:
	$a0
}

        
