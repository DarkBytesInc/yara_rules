rule Win_Spyware_Banker_1150
{
strings:
	$a0 = { f97c582091ea81205e6f1048f0830fff714dcdfd5c5e127141a03d3d4f273fff289de33298601fee9c272703241a3b697ece0b807d9dcc7c0a7046c5bf58434f1b598fff215a5bcf65d13dfddc17542b5e4d8e8c6a3de58a376f }

condition:
	$a0
}

        
