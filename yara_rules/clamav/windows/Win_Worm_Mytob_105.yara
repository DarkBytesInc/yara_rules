rule Win_Worm_Mytob_105
{
strings:
	$a0 = { 1b23ed5166a9f20c593d8bed7f305301f3535e5b516a2883c40459f973053db8420d1184ff5287c95a6812faffff5853506a6258585be202e3004181eb00000000f97b057f037401f85381c9000000005b80c100c0cbc88bf65301c389d85b565ed9d055760505000000005dc0cc88f5 }

condition:
	$a0
}

        