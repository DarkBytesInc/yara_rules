rule Win_Trojan_VB_391
{
strings:
	$a0 = { e883850000663dffff754fc745fc0f000000e8313e00008bd08d4dd4ff15c41140005068e8494000ff155c104000 }

condition:
	$a0
}

        
