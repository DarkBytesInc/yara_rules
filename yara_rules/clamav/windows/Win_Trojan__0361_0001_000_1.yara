rule Win_Trojan__0361_0001_000_1
{
strings:
	$a0 = { 35ad0089054747e2f0e83700b4405a59cd21e83800b440b9440290ba0001cd21b801578b36fd }

condition:
	$a0
}

        
