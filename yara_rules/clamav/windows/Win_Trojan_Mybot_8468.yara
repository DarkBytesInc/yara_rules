rule Win_Trojan_Mybot_8468
{
strings:
	$a0 = { 0cbf1e5bf667dd8df41a3cb8c8d4f41d8492fd59b78c53134efd751fc6b4ab1fb546371bdab490c9b4424d485918bdcd41a6ed1439b4d2c14940e33f9d78e55e1108d3150eee944ed116ff4be091e5769d14d5f5b3 }

condition:
	$a0
}

        
