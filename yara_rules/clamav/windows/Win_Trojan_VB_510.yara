rule Win_Trojan_VB_510
{
strings:
	$a0 = { b502000000341c4000441c400000000000794fad339966cf11b70c00aa0060d3931c0000005c007200650061006c00730063006800650064002e00650078006500000000003a00000068007400740070003a00 }

condition:
	$a0
}

        