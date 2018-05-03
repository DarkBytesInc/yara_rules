rule Win_Worm_Rastam_1
{
strings:
	$a0 = { 21b400cd1a89d381c35a00b400cd1a39da72f88b16be018eda8b16bc01424289d6ac2c0d75fb8845ffb441cd21cd204861696c652053656c617373696520 }

condition:
	$a0
}

        
