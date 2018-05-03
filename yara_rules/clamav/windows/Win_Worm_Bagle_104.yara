rule Win_Worm_Bagle_104
{
strings:
	$a0 = { 979e15631d7eab619c65c7f9a08fa1128f12a7a835d7eaa60c34476f965cbd1e56abd5ec5e7a2b58ded642ed6852b8973a0a2c7545516fcf5d37341c58a0acc0f32cdd2dfb8bd1125c0145a4d3ce70b8508ba02c706b279bc1534d4dab06b0e5 }

condition:
	$a0
}

        
