rule Win_Trojan_Delf_85
{
strings:
	$a0 = { f8a92b088701b8ff246d6972636578650a977c09803310be046bf281316a3de87b80aa0e3c01482b477cacc3a6bf818113807c02ff5c74c0ba943a0be464bda89687aa }

condition:
	$a0
}

        
