rule Html_Trojan_IRCMimic_3
{
strings:
	$a0 = { 6e303d6d696d6963206265746120332e312e315345525645523a696e6665737465642e6d696e652e6e75 }

condition:
	$a0
}

        
