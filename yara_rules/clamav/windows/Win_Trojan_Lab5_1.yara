rule Win_Trojan_Lab5_1
{
strings:
	$a0 = { 31029a0d00a4019acb0096019a8c008c019a520356019a7c031d019a3703e8009ac303ab009a3100a7005589e5 }

condition:
	$a0
}

        
