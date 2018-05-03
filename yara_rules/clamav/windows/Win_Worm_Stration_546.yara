rule Win_Worm_Stration_546
{
strings:
	$a0 = { 64627501000000004c63607c6a476e616b636a0f00000000ffddcce8cad7db }

condition:
	$a0
}

        
