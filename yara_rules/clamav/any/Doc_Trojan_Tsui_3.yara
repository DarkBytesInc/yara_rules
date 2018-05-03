rule Doc_Trojan_Tsui_3
{
strings:
	$a0 = { 6e65776974656d2e626f6479203d2022bdd0b6f1a7b4b0dda8e9452d4d41494ca65e74766273b773bb44b3a12ca7daadccb14eb065b17a4e4f4b49412038383130a4e2bef7a440b0a622 }

condition:
	$a0
}

        
