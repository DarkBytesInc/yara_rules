rule Win_Trojan_Tepfer_28
{
strings:
	$a0 = { 68fc3f400083042404681c3140005f83c7928b3fc1e7108bcc8d6f3cc98be103fd83c71d33c9330f84c97e1a5f51b01c2ac87e0a581c7c7705e982feffffb825304000ff50ff6a7c59e2fefa000000096715003a0000000acccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc }

condition:
	$a0
}

        
