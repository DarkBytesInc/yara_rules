rule Win_Trojan_IVP_26
{
strings:
	$a0 = { 8d9e????8b178d9e????8a0732c28807438d86????3bd875f1c3 }

condition:
	$a0
}

        
