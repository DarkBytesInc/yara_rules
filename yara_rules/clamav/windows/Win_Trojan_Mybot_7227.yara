rule Win_Trojan_Mybot_7227
{
strings:
	$a0 = { b74c7e15148ee0713fb5feca9d99e687434cdc6e8ee918a28d2bf8f6d6f14693b72b093433f263b9183e5c0488d4b53d6960cdb4f3e784e61fd472484dd22d88ab1d9815cabe4a25e992da536104 }

condition:
	$a0
}

        
