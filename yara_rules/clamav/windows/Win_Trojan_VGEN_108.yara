rule Win_Trojan_VGEN_108
{
strings:
	$a0 = { 83ef032e817d0358457526eb0190e81601721be83f007303e93901e8d900e81101e895001ee87c001f8cc3e8a500e9 }

condition:
	$a0
}

        
