rule Win_Trojan_VGEN_274
{
strings:
	$a0 = { 0a008db6f201bf000157a4a4a4b8a054cd213d0312743f1e58488ec08b1e020081eb1600891e020026812e03001600 }

condition:
	$a0
}

        
