rule Win_Trojan_Bancos_831
{
strings:
	$a0 = { 696e7465726e657462616e6b696e676361697861000000000000000000000000 }

condition:
	$a0
}

        
