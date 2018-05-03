rule Win_Worm_L_60
{
strings:
	$a0 = { 8bfbf2aef7d12bf98bf78bfa8bd183c9fff2ae8bca4fc1e902f3a58bca8d9424ac00000083e103f3a4bf4471400083c9fff2aef7d12bf98bf78bfa8bd183c9ff }

condition:
	$a0
}

        
