rule Win_Trojan_IRCBot_676
{
strings:
	$a0 = { 683e0c903f91298f98d2cbdfc271af1ea84a25b37365ac5a6bc6f8821be1ac6a4fbef4821b611c5ebfcaaa8b1b61e8ce84622c8a9b62adb0774aad925bb8af4f744aad926b98ad4f744aac8a5b48261fb4fa68b2f3e8d07abf89fcb12bb10dd3a007be88 }

condition:
	$a0
}

        
