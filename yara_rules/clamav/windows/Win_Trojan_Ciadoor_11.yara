rule Win_Trojan_Ciadoor_11
{
strings:
	$a0 = { 430049004100200031002e00330000002600000053006f00 }
	$a1 = { 54fff5000000006c70ff0450ff346c50ff6c6cff5e80001800714cff3c6c50ff0470fffc582d48ff6c4cff7158ff2f50ff6c58fff5ea }

condition:
	$a0 and $a1
}

        
