rule Win_Trojan_Mybot_8059
{
strings:
	$a0 = { 25da9c0e0c2d7be22f2b672af9cc0bfb7f74109736c03856742afd2b01524e04780ae25f0161014189d8eb07c9d27c64af27f8ff21ab473c0a4685571f75d9c625d2335d5f3c2e3b9026622f508212f0e898ef25f5857c98d91889c37ed2cf10b20441834409f0c36a5f40b7e61ee8c7a79283ca82718064b7f372130856cc0e53b86c4f8a6243397b20 }

condition:
	$a0
}

        