rule Win_Dropper_Agent_34530
{
strings:
	$a0 = { 6a01684827400068482740008d45d8e846fcffff8d45d88b15dc474000e86cf7ffff8b45d8e81cf8ffff50684c2740006a00e8e3fbffff84db0f84fafeffffa1d4474000e8fdf7ffff50e853fbffff33c05a5959648910681b274000 }

condition:
	$a0
}

        
