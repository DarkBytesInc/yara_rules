rule Win_Trojan_Bancos_1730
{
strings:
	$a0 = { 03bf4fc604d0f3bf390992598240f6fc1d87a0b959782fc06fd315f2d23b7eb86f5add87b39a19f030a4cc89d8ff676b1763469e8762fa41db294249fb486f8d128705e881cb }

condition:
	$a0
}

        
