rule Win_Trojan_Bancos_986
{
strings:
	$a0 = { 2f43acf1dd3c7dddf736e92fd9c59da5c69078a8aab239ea7606d929122a4bf2f45d13a1f9c94e17ffb8e7d63c1988449b934f22cdb42f7be343c0dae71497c0a38477981750e8af4db79a059c038788c128a0bafd }

condition:
	$a0
}

        
