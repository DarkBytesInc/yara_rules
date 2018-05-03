rule Unix_Worm_Ramen_3
{
strings:
	$a0 = { 23212f62696e2f73680a2e2f62696e64202431202d65203e3e202f64 }

condition:
	$a0
}

        
