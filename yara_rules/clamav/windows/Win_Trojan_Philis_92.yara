rule Win_Trojan_Philis_92
{
strings:
	$a0 = { 9bdbe2605681f6882800005ee8000000006081c1471d0000615ab84201000057f7df5f5133ca5903c281f73621 }

condition:
	$a0
}

        
