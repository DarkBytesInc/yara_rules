rule Win_Trojan__0023_0005_002_1
{
strings:
	$a0 = { 8becc7460200405d58ba9a10b91310cd21b80042505833c933d2cd2150558becc746020040 }

condition:
	$a0
}

        
