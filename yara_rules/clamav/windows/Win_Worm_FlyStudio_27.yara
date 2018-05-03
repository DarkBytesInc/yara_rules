rule Win_Worm_FlyStudio_27
{
strings:
	$a0 = { 5?5?5?5?5?f95?0f82 }

condition:
	$a0
}

        
