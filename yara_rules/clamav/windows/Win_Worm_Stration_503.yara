rule Win_Worm_Stration_503
{
strings:
	$a0 = { 110411101658210a120b090a04012017170a1743060a01005840014311171c5840016500000000072035202127691538263135302d1d3a2720353838313054000000002a0d180d0c0a442b0c177900abe7e3eda9e6edeaabf4f6aae7e3ed8400000000bfbdb6beadabb0b1b2b1b6b3bdaaacb1b7b6bcb9abbdf6bbb7b5d800c0ced9c5cec7989985cfc7c7ab000000f6c7d0d4c1d0f0 }

condition:
	$a0
}

        