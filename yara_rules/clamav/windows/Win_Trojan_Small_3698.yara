rule Win_Trojan_Small_3698
{
strings:
	$a0 = { b35fa3e7adb635a8c530dfe65dc8b3ba9d60208fe563cba6e024e4fc5c380cf7b3caccf9c548dfe65db5b3186060cb292179ca1b8178cabc65700ba7bcbe2802b62322fec560dba65dcad3a57298dbe65db0cabc99700ba7e85036a7c78321115d5fe1fa6da0cb2b1dd5fd319a90dbe65db6ca }

condition:
	$a0
}

        
