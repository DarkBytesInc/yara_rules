rule Win_Trojan_Tepfer_24
{
strings:
	$a0 = { bffc3f400083c7045768143140005f83c7928b3fc1e7108d773b8b06c1c80803f883c71d33c9330f84c9761a5f51b01c2ac87e0a581c7c7705e9eafeffffb861304000ff50ff6a7c59e2fecd030000c9da2a003a0000000afefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe }

condition:
	$a0
}

        
