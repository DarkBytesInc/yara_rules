rule Win_Worm_Autorun_319
{
strings:
	$a0 = { 6801504000e801000000c3c39f6cd37dbb1cf42fff2c9eed46f3fe2cde683206eec36b32f33469ec5e4a }

condition:
	$a0
}

        
