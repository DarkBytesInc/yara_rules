rule Win_Trojan_Death_6
{
strings:
	$a0 = { 47696167ac01f72e9010322003cc541bace40cadd2d71f14988aafb2bdd4b9500124e490add41bf2023f0564ad2170ad24b50d08498005a5b1945cf2d0b990d07f002f }

condition:
	$a0
}

        
