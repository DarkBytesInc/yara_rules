rule Win_Trojan_Lowzones_10
{
strings:
	$a0 = { 65722e70636822202d5958202d466f22433a5c446f63756d656e747320616e642053657474696e67735c53776565744269747465724c6f76655c536b72697662 }

condition:
	$a0
}

        