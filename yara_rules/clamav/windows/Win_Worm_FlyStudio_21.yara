rule Win_Worm_FlyStudio_21
{
strings:
	$a0 = { 5?5?5?5?5?f85?0f83 }

condition:
	$a0
}

        
