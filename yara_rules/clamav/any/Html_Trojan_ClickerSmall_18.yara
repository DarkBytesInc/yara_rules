rule Html_Trojan_ClickerSmall_18
{
strings:
	$a0 = { 69636b62616e6b2e6e65742f3f783000782f6565b7db61df186d3237332b77002e702f7570ecbffbf6636f6d6d2e6465722e092f6367692d62696e2f46b5c37e }

condition:
	$a0
}

        
