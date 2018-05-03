rule Win_Worm_Stration_360
{
strings:
	$a0 = { bbd06e5b426719e0791ce064cfe58632c1513e24932bd6217849e912e2f31a08bd4770386f739defdf69b1ced71bbf910da1c4dde90b4a6a13018796ed833d14 }

condition:
	$a0
}

        
