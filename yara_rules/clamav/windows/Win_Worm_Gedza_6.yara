rule Win_Worm_Gedza_6
{
strings:
	$a0 = { bf13000000bb606841006affff35d47a41008d45f48b13e842edfeffff75f48d45f08b16e835edfeffff75f08d45f8ba03000000e889eefeff8b45f8e8c1effeff50a1a87a4100e8b6effeff50e88008ffff }

condition:
	$a0
}

        
