rule Win_Worm_Petik_9
{
strings:
	$a0 = { dce0e4e823232323ecf0f4f8469e2323fc00310408464646460c101418464646461c202428464646462c3034384646464640484c5057011566007f5dfdbf9200492d576f726d2e584657fd64fd2ff856f92062792016202863293230ffdf824bec204d7420496e204672616e6365 }

condition:
	$a0
}

        