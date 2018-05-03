rule Win_Worm_Stration_438
{
strings:
	$a0 = { 94d3c3f223dd2576d05a2143032bb2f775e556d422ef1feebaa70c5ce9ae908b33b1a9f18f4628a399c6187ab4ee092a4caa9df7dbf5d0c873e91626f57703be8e1370d003b76dca2c8478d7fa80916b }

condition:
	$a0
}

        
