rule Win_Trojan_Saje_1
{
strings:
	$a0 = { 2e436f707946696c6520577363726970742e53637269707466756c6c6e616d65 }

condition:
	$a0
}

        
