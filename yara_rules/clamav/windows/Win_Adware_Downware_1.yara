rule Win_Adware_Downware_1
{
strings:
	$a0 = { 4004430437043a0438043a0000000000b0040200ffffffff09000000700072006f006d006f002e006500780065000000b0040200ffffffff2500000068007400740070003a002f002f00730065007400750070002e0064006f0077006e0076006900730069006f006e002e0063006f006d002f00700072006f006d00 }

condition:
	$a0
}

        