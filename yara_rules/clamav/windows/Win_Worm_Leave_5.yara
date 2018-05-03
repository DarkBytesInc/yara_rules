rule Win_Worm_Leave_5
{
strings:
	$a0 = { bfa0a64200f2aef7d12bf98bc18bf78bfb8d9ad5320000c1e902f3a5 }

condition:
	$a0
}

        
