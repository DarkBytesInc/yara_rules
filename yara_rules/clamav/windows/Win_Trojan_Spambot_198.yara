rule Win_Trojan_Spambot_198
{
strings:
	$a0 = { bd832a8517ffffffcd5124b270b70afde197e18ddb99b0af3607cf440189bf7571ecffffffe329af4faf6f56632032a406cd3a05267d2837907e9cc8eb25d707ffffffff9291257b8f5b5f1bb732740fdeaf7fd0bde7319facee0def0d6ff1ef8596e603fffff0ff9c25ed6ebbd1 }

condition:
	$a0
}

        
