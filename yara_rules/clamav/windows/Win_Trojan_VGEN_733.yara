rule Win_Trojan_VGEN_733
{
strings:
	$a0 = { 06e85a00b81430d4ffb430cd2139d8742380fc05721eb021e852002e899e92032e8c869403e84e00720a061fba5e02 }

condition:
	$a0
}

        
