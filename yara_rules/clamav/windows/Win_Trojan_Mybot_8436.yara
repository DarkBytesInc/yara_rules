rule Win_Trojan_Mybot_8436
{
strings:
	$a0 = { 6155cacf734a0945e1e3dc0b537cb994633d2426eab4d577653e32ed018c2126cf76cb3c9d07fb5f45ff38d0b78be2d8ff8cd3cc9b370a01301a4ae9dd93f1e3c8cfccd9e35a57328398dcb9d8d47a1d5f3ad9d01f }

condition:
	$a0
}

        
