rule Win_Trojan_VGEN_696
{
strings:
	$a0 = { cd218cd82d11008ed8803e00015a754fa103012d40007247a30301832e1201508e0612010e1fb9d801bf000157 }

condition:
	$a0
}

        
