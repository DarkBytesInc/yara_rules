rule Win_Worm_Stration_485
{
strings:
	$a0 = { 3546ba68bfe3573d644d746cd65ecc664dd9659023365dd2553306504ea2ef856c194f885cb14c74b4c2b6ecbf897778b47134ba7b211dbb5304faef8d7a5a3b5d3e70 }

condition:
	$a0
}

        
