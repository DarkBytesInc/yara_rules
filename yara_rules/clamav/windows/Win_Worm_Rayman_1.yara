rule Win_Worm_Rayman_1
{
strings:
	$a0 = { 6175746f657865632e626174005261796d616e207361793a202727497427732074696d6520746f20676f20686f6d6520616e642073687574646f776e20796f75 }

condition:
	$a0
}

        