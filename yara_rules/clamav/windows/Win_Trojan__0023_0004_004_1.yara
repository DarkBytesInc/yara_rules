rule Win_Trojan__0023_0004_004_1
{
strings:
	$a0 = { 0550558becc7460200405d5833d2b98700cd2150558becc7460200405d58ba9a10b91310cd21bf }

condition:
	$a0
}

        
