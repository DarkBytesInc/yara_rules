rule Win_Trojan_Dref_1
{
strings:
	$a0 = { e8000000005a81c2????00009268ff000000595005fc03000089c68136335134004983f9007c0583ee04ebefc3 }

condition:
	$a0
}

        
