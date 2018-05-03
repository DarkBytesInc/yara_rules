rule Doc_Trojan_Alcaul_21
{
strings:
	$a0 = { 7061756c }
	$a1 = { 6f626a203d20416374697665446f6375[0-25]436c61737354797065 }
	$a2 = { 2e41637469766174654173 }
	$a3 = { 3d6f626a }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
