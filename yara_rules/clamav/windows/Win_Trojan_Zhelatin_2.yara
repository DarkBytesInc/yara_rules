rule Win_Trojan_Zhelatin_2
{
strings:
	$a0 = { 80f940731580f92073060fa5c2d3e0c38bd033c080e11fd3e2c333c033d2c3cc80f940731680f92073060fadd0d3fac38bc2c1fa1f80e11fd3f8c3c1fa1f8bc2c3 }

condition:
	$a0
}

        
