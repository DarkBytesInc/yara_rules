rule Win_Trojan_GreenBay_1
{
strings:
	$a0 = { 64642c2d2a6c000019642c2d2a6907456e64436f6465196464646507456e64436f64651964641a1b }

condition:
	$a0
}

        
