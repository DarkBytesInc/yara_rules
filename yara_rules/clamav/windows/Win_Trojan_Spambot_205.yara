rule Win_Trojan_Spambot_205
{
strings:
	$a0 = { d18dffffffff5af03ef077eb2eb30bd586b7f5971b4adef264b082f15e5066a4d4b277ffeadcf807f8ffeef94a385e724f11a3f8070ffda1991231085cc7feffffbf3bcaf454f8cbec5fc5bf7cee29a6ff6d463ef98adec58bdc3ce17741ffffff3f5f55e7c57acf6e7e6a409312 }

condition:
	$a0
}

        
