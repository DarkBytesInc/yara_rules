rule Win_Trojan_VGEN_279
{
strings:
	$a0 = { 0a008db6f101bf000157a5a4b8a054cd213d0512743f1e58488ec08b1e020081eb1500891e020026812e0300150083 }

condition:
	$a0
}

        
