rule Win_Trojan_VGEN_548
{
strings:
	$a0 = { 01010503008bf08c845904b4fcbb0164cd2181fb7553750d8bde81c3570481c65b04e9f80033c08ed8a1130448a313 }

condition:
	$a0
}

        
