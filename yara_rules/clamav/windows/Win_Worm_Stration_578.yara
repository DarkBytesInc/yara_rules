rule Win_Worm_Stration_578
{
strings:
	$a0 = { 0a0a845b716c4e6a7a2fffffff6d66405e1f00f3d9c4e5d2d4d8c5d3fbdec4c3f1c5d2d2b7696d2cfe5f68ff412d2c307a72721e877f8ea9bcafa9a8addd00342812ffd00df32f5c1f2d3c17292c30 }

condition:
	$a0
}

        
