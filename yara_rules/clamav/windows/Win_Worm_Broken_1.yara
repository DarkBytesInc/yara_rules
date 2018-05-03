rule Win_Worm_Broken_1
{
strings:
	$a0 = { f506e5c9fdd6826662626482e76ed6787068646262822af90610efd6f9eb6e82f506e5c9f9822c1a }

condition:
	$a0
}

        
