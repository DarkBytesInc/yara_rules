rule Win_Worm_Stuxnet_8
{
strings:
	$a0 = { 6a00ff150c300010a31c400010e8fe0100006a00ff1528300010cce9f0010000e8eb01000033c0 }

condition:
	$a0
}

        
