rule Win_Worm_Stration_604
{
strings:
	$a0 = { 66837f0a08750e8d463050e80a0227de85c05975988b46440147148b463889471883a68000000000c6462c008b472c03471801462033c05b5f5e5dc3558bec53 }

condition:
	$a0
}

        