rule Win_Trojan_Proxy_56
{
strings:
	$a0 = { 97b9447584b8de8ea16dfd6e7116231c7f714dd61b4e067f1cfc9a6dfb1f643f54703ad688614901bcf422410a667bfcea06effeff12fbd4fd74678d1ee6af5313395dec4171ab46531755ba48eed12eece30a12168dfac94a47d74ac621d32e2f093263 }

condition:
	$a0
}

        
