rule Win_Trojan_Bifrose_169
{
strings:
	$a0 = { 012bcad782d289f8d8a7610076eb7ff21c4086a900654463e2d0ff81f10fd1583005c1790e0dfed4698201ccdd8543cf84cdf427c000e9021a3bdf82e10100f9f79110a7 }

condition:
	$a0
}

        
