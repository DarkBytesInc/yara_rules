rule Win_Worm_Dumaru_5
{
strings:
	$a0 = { 0cb508edfffbee81c61037803e00751e40e83139392e3136362e01cf1fec }

condition:
	$a0
}

        
