rule Win_Trojan_Spambot_171
{
strings:
	$a0 = { 5165a216696a4733c51e89ddb0fc8bb888ffffffffee86dfbfd8ac5e004a3ebf4b0717b39422e6d5cca8698841a7f6cf9011eb2f33ffffffffd6bede85ebb8a5358215cef7bb731bbf54f0b2899d4ec8c5677d1f4b8a180819ffffffffce0b994e677ad9963848d28b421bee170e }

condition:
	$a0
}

        
