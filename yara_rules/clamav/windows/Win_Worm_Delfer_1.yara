rule Win_Worm_Delfer_1
{
strings:
	$a0 = { 4640bafc654500e85cdffaffeb2b8d4640ba0c664500e84ddffaffeb1c8d4640bab0664500e83edffaffeb0d8d4640bab0664500e82fdffaff8b45fc8946388bc6e892cdfcff8bc38b10ff52448b45f8e8e7d0faff8bc3e8e0d0faff }

condition:
	$a0
}

        
