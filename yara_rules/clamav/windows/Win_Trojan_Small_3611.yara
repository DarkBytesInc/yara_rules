rule Win_Trojan_Small_3611
{
strings:
	$a0 = { b3580f29ca18f9310b03f51fe15ab660cbedd11fa2bda620cb02fa4b9b8e8f20a2068dac0f27c970cad93030ceeafa71350ba4361f14e5201b02ba7cdb42a5a9d28de944e38db4ad1e04f7701c02ba64dc42a5abe2 }

condition:
	$a0
}

        
