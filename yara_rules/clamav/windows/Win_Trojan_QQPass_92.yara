rule Win_Trojan_QQPass_92
{
strings:
	$a0 = { ffc3e9f8ebffffebeb8be55dc3000051512e6578650000ffffffff0c0000006e706b63727970742e73797300000000ffffffff0d0000004c6f67696e4374726c2e646c6c00000053 }

condition:
	$a0
}

        
