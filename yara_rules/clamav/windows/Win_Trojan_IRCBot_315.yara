rule Win_Trojan_IRCBot_315
{
strings:
	$a0 = { 3f565550f62a72484f1e19e7a93b51181726b85c1f4919181722c04215dcbb792d0441fe0aebe7cb985233c76af30fd3281a1ccf32003878b8c498ac1f00a4eec0eca0fc2729acb62e82b7ce37e4c8aaf542dfcbcdd4b3 }

condition:
	$a0
}

        
