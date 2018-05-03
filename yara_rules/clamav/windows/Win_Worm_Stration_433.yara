rule Win_Worm_Stration_433
{
strings:
	$a0 = { 9534f64bab2ee6a872877844128457c5dcdc976bc41c18b8e59bfd661cce667357af8f717421b3a1199baf57aebe78851107a99cd907de8a354af7008298c9f381e0f3d44d68cdb95996f9dafe5aa632 }

condition:
	$a0
}

        
