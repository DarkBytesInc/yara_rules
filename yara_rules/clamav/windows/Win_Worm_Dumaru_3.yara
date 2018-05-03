rule Win_Worm_Dumaru_3
{
strings:
	$a0 = { 354005406d61696c1c2e72752b01543868748e703a2f2a7348872e6e65f06669726dfde4636fea2fe867f62d7e62786e }

condition:
	$a0
}

        
