rule Win_Worm_Dumaru_7
{
strings:
	$a0 = { 3139392e3136362e0132009aeff9837d66f3a52c3b6a026a358d850531b5bbfff7508d45fce4043e83f8ff }

condition:
	$a0
}

        
