rule Win_Worm_FlyStudio_23
{
strings:
	$a0 = { 5?f95?5?5?5?5?0f82 }

condition:
	$a0
}

        
