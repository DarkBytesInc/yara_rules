rule Win_Trojan_Tepfer_49
{
strings:
	$a0 = { bffc3f400083c70457681c3140005f83c7928b3fc1e7108bcc8d673c588be103f883c71d33c9330f84c9761a5f51b01c2ac87e0a581c7c7705e932ffffffb859304000ff50ff6a7c59e2fefb000000096764003a0000000afefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe }

condition:
	$a0
}

        
