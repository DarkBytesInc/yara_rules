rule Win_Worm_Stration_732
{
strings:
	$a0 = { 8b44240883e8007414487524ff742404ff1524100010e8abfeffffeb13a0002200102c3f341da200220010e885ffffff }

condition:
	$a0
}

        
