rule Win_Dropper_Agent_33954
{
strings:
	$a0 = { 53e804f5ffff85c07436a1d476400050a1d0764000e820eaffff8bc8ba24514000b80a000000e863f6ffff8b15d0764000a1cc764000e82ffaffffe922010000 }

condition:
	$a0
}

        
