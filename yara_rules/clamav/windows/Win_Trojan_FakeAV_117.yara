rule Win_Trojan_FakeAV_117
{
strings:
	$a0 = { 21c8038dc4feffff21459c3b85a4fdffff7631b9fc0f0000118d44ffffff118d04feffff29c12b8d5cfeffff81f886040000741c31c801c8ff8d10feffff2985bcfdffff0b8d98feffff138d7cffffffff85acfeffff218decfcffff2b8554feffffb96b }

condition:
	$a0
}

        
