rule Win_Worm_Youzer_1
{
strings:
	$a0 = { 63686f204f66660d0a4543484f204154442c54393131203e434f4d320d0a }

condition:
	$a0
}

        
