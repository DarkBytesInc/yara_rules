rule Win_Spyware_Banker_3359
{
strings:
	$a0 = { 857e3344a87ed5d48bd594832e293303772e14f2fc24541f50aabe9e22d61250a1802ea1fa4223b6f3f51c4c2ded21cc2f82d3b13572efa10d9a2860c87de006776839265f9edda87dbfd4dc33c3f4dd996c4f841a }

condition:
	$a0
}

        
