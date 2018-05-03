rule Win_Worm_Stration_685
{
strings:
	$a0 = { 1b5f5c855aa28849e4a06f2c574b96669b917b6f2d4d344b6f53446f50c8bb59e2779f23ad666eedb3df45e6e4243fe02f3778c633d35f }

condition:
	$a0
}

        
