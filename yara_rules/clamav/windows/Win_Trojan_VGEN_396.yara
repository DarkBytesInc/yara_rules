rule Win_Trojan_VGEN_396
{
strings:
	$a0 = { 8db60b02bf000157a5a4b8a054cd213d3412743f1e58488ec08b1e020081eb1500891e020026812e0300150083 }

condition:
	$a0
}

        
