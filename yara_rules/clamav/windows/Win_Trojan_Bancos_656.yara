rule Win_Trojan_Bancos_656
{
strings:
	$a0 = { 11f50ca2a6c0bd8e6ddd04d1f3bb0160059a1de19c577029c1d441318925765656e196e5fa384b94fc2eaee5720f90c28c0fd803fc13b3c3c7d77a940ff72450056f5516 }

condition:
	$a0
}

        
