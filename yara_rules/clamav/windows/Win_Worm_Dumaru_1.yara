rule Win_Worm_Dumaru_1
{
strings:
	$a0 = { dc1c8620cc09470f6d077970686f74232e6ab967205b01b02e6578e48f9ea7158b6d0e010214156fa9080120e1319dc2 }

condition:
	$a0
}

        
