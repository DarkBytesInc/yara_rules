rule Win_Spyware_Banker_3462
{
strings:
	$a0 = { b6e42f0b866742ad8bd5c689b657f2d87bb70e067401b9a9a921adc42abcaa2d94d2b70a1e27edd979c895010df7f3efd9782c529f5301b5b85ad45ada02f3fe4a9f35a3b89fa69dacb7d5a9b795e45f3d5855e7659356f6e3d8d902ef49032520aba9c98afbf721ea0ceaa8ad65d6fdfdaf0b }

condition:
	$a0
}

        
