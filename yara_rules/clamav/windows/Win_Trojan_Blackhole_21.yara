rule Win_Trojan_Blackhole_21
{
strings:
	$a0 = { 8bc3baa0494600e80400faffff338d45f0e8a6d1ffffff75f068244946008bc3ba03000000e89e00faff8bc3ba60494600e8dafff9ff8bc3bac4494600e8cefff9ffff338d45ece81cdeffffff75ec68244946008bc3ba03000000e86800faff8bc3ba60494600e8a4fff9ff8bc3bae4494600e898fff9ffe8fbcefdff }

condition:
	$a0
}

        
