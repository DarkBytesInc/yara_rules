rule Win_Spyware_WOW_16
{
strings:
	$a0 = { 68644540008d55f0a1005140008b00e8c5f9ffffff75f068744540008d55eca10c5140008b00e8aef9ffffff75ec68844540008d55e8a1045140008b00e897f9ffff }

condition:
	$a0
}

        
