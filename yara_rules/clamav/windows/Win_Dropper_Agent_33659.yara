rule Win_Dropper_Agent_33659
{
strings:
	$a0 = { c098909869a1682f4e6b70088c5c2417aff490fffd3a0450ec87fd89289ab23cf0403d4c143a1c62bf78f3c93fbc5057f645d47837a61fc0c6e87a33bfb456bbc8106cad679560ceba3e3209fec19669 }

condition:
	$a0
}

        
