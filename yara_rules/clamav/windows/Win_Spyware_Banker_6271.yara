rule Win_Spyware_Banker_6271
{
strings:
	$a0 = { 2a485a914fee57dfae68ea1b32e74fce5fb7d5f5fe6ee652eb6b2bc2f825e27981844473782cdf11e4dc74369e897bb2c872e6f21d2969eca553233a84c04f9dee9ac12dbdab82ca01619346caf6332cf16f65d7f9b6a5c8e83619e3764339 }

condition:
	$a0
}

        
