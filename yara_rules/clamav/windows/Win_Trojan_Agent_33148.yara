rule Win_Trojan_Agent_33148
{
strings:
	$a0 = { ad58fc3ab2c5e861b6969947bf29ab77405d251e02fba70e7f8fff5706574bea9f34fac90a3477fe90e6d477d2ded7cad32643cd60b65264217cbb67d8d3157123001a6cb3406deb8d3121f095c7 }

condition:
	$a0
}

        
