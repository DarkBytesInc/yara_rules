rule Win_Worm_Kelvir_49
{
strings:
	$a0 = { 6f006d002f007000690063002e007000680070003f006300610074005f00690064003d00310031002600660069006c0065003d0069006d00670037003400350037002e006a007000670020006800650068006500000000000e0000007b0045004e0054 }

condition:
	$a0
}

        