rule Win_Trojan_VGEN_596
{
strings:
	$a0 = { 83ef032e817d0358457526eb0190e80d01721be83f007303e93001e892001ee879001fe8c800e800018cc3e89c00e9 }

condition:
	$a0
}

        
