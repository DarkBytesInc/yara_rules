rule Php_Trojan_Agent_37000
{
strings:
	$a0 = { 61727261792861646d696e203d3e20617272617928226e616d6522203d3e2061646d696e2c20227061737322203d3e20626f745f70617373776f72642c20226175746822203d3e20312c2273746174757322203d3e202261646d696e2229293b }

condition:
	$a0
}

        