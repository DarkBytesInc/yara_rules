rule Html_Trojan_Fraudpack4804_1
{
strings:
	$a0 = { 74463900003300003976005800774e00003570574f005366000000005300004d4b31000000000000003000000000773100003444000000000065000065424d006437540000493176000000740000006a00000000006932007000335800000000580078000052335a690000730074000053007a3131770000396500520000720037006233416f006b000000486d5a0038556c000000004e004d4d4500 }

condition:
	$a0
}

        