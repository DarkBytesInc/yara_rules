rule Win_Trojan_Vgen_119
{
strings:
	$a0 = { 4c902a2e636f6d0000433a5c436f6d6d616e642e436f6d00433a5c4175746f657865632e42617400433a5c436f6e66 }

condition:
	$a0
}

        
