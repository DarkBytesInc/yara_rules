rule Win_Adware_Xpantivirus_1
{
strings:
	$a0 = { bbe335cc00eb3066adc1e002c1e006c1e002c1e00666add1c0c1c00cc1c0039381c3??????0?89d866abc1c80590c1c80b66abe2d2eb5ec1e91f51680000ffff68567e45ff68d585ba00e81300000089cab812????f09681c6ee45f30f89f756eba55589 }

condition:
	$a0
}

        
