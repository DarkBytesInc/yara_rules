rule Win_Trojan_PolyEngineSamplesGen_1
{
strings:
	$a0 = { 445343452076312e3020580e5051e80000582d1100b104d3e88cc903c150b8230050cb5953065756558cc0060e07bf94 }

condition:
	$a0
}

        
