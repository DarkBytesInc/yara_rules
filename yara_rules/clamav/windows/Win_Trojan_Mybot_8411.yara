rule Win_Trojan_Mybot_8411
{
strings:
	$a0 = { 280ddcb431b412c44c2ea1dd79d34d1fb6c518667c7095914867b2add7481099f75f443772c151e66cad00ecf9f95de380ebf774ea5c844bf64ba13a0038a7d634e4b4979ddb99b20bbe2f2fd9d02a0e180b16e190 }

condition:
	$a0
}

        
