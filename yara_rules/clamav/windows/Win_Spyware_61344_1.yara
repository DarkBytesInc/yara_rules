rule Win_Spyware_61344_1
{
strings:
	$a0 = { 5053515257561e06550e1feb11905c73797374656d2e6c6f67000000000033c0e460a356 }

condition:
	$a0
}

        
