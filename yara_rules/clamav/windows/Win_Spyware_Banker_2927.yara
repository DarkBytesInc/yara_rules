rule Win_Spyware_Banker_2927
{
strings:
	$a0 = { 767aa611eba425adb0d73dab8a2ecfc9faa7724f115b083aed88e398acd782d1a189823f73cf82bd50eb856a78fe78b794dcb6fed41052bd28d21dd5cf83b19f76c5ce7a0c56a55ca663101881a84390a626f829e56b4a0ed89c0bde2b1d3f9f3ed9d0e1bb97b91c6d247a7f1c4a }

condition:
	$a0
}

        
