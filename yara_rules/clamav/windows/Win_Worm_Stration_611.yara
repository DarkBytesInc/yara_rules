rule Win_Worm_Stration_611
{
strings:
	$a0 = { 518b4c2428528b5424285152ffd05b83c418c21000cccccccccccccccccccccca14439430083ec1085c0568bf17545a1649642008b0d689642008b156c964200 }

condition:
	$a0
}

        
