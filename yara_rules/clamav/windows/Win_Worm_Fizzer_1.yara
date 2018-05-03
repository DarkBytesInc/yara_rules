rule Win_Worm_Fizzer_1
{
strings:
	$a0 = { 65fcf0af4b1814080cf169800cf4248cf82868e9bc692ee03413290832f26f64d0f6b2dc4bb84f406a94a49faa2c68658a }

condition:
	$a0
}

        
