rule Win_Trojan_Spambot_163
{
strings:
	$a0 = { dfdde8b579f47111b49ccf05aa1ae28b76e174ec33affeff8fa6ff8cc2d08437729da08d99393a93b8259fd06fffffffff939dcb6fc80dd3247e223b7bdfef50071c2e33c8fa2fc27a063fa8f02b1468b5ffffffff15da2c7edd0a0639f44575c92ef31704cf76265b31f7d652bc }

condition:
	$a0
}

        
