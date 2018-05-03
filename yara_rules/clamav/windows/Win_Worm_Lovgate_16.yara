rule Win_Worm_Lovgate_16
{
strings:
	$a0 = { 3559f1110701cc2ddc3cf346e854080cae9eb356633f45537b82ea323b532a6d18f64d2c84289b0f0c1437495acbba08 }

condition:
	$a0
}

        
