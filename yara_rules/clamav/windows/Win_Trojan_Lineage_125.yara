rule Win_Trojan_Lineage_125
{
strings:
	$a0 = { be413cb1ce6b31bead09017658d9db89aeeaf5b163466f94bea9a4102898d4a8d48261cdf14f1cf740d1b7c5f225608ee78c1ded8c5776ee361aa4d7197ff10c312c7f417fd2fcfb4a16f6e5a0cc027efb346e900a3d8534bf58c9aed3c75ab76a8deaa7 }

condition:
	$a0
}

        
