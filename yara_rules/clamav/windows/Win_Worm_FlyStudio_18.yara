rule Win_Worm_FlyStudio_18
{
strings:
	$a0 = { 5?5?f85?5?5?5?0f83 }

condition:
	$a0
}

        
