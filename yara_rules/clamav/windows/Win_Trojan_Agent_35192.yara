rule Win_Trojan_Agent_35192
{
strings:
	$a0 = { 405d251e02fba70e7f8fff5706574bea9f34fac90a3477fe90e6d477d2ded7cad32643cd60b65264217cbb67d8d3157123001a6cb3406deb8d3121f095c7ef6d2ff7e3118102d1b4e7c90e78a516 }

condition:
	$a0
}

        
