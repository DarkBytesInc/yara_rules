rule Win_Trojan_VGEN_287
{
strings:
	$a0 = { bd0a008db6f001bf000157a5a4b8a054cd213d0812743f1e58488ec08b1e020081eb1500891e020026812e0300150083 }

condition:
	$a0
}

        
