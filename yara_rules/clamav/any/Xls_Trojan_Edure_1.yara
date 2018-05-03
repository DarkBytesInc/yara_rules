rule Xls_Trojan_Edure_1
{
strings:
	$a0 = { 433a5c6d736f66666963655c657863656c5c786c73746172745c[0-40]6269727468 }

condition:
	$a0
}

        
