rule Win_Spyware_61353_1
{
strings:
	$a0 = { 558bec6aff68986d4100681808410064a10000000050 }
	$a1 = { 7265737369676e616d }
	$a2 = { 5c006c006f0067006f00660066002e006c006f0067 }
	$a3 = { 50004f00530054 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
