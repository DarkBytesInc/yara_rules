rule Win_Trojan_IRCBot_344
{
strings:
	$a0 = { dcce8dac5976550425fcb78750916941dfa7cb8f968851642396a9834e7176c84de818c2a2822ad018bcb3f9ad85654c1bcc93d30b5a4d193f9db0c5d64b71fb5958659c764879d7adfde3fbfa069f7e }

condition:
	$a0
}

        
