rule Win_Trojan_Small_3770
{
strings:
	$a0 = { dd492c5fd80a45b5541e6dafabb02db2bd2e409f559b14d158462ce2195f2bd4795e2b755d566c5fb4a489baae0983b6bd463c5f55b0345e6a7e3c9f55962b7591566c5fe036975fbf6982c9554542b365862ce415bb5eea92763c9f559c2b37da06a184ab4504e0d1762bbcca4e825e2cc790 }

condition:
	$a0
}

        