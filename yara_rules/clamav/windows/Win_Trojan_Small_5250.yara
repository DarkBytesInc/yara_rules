rule Win_Trojan_Small_5250
{
strings:
	$a0 = { 86ec68f592f5a8b95ab4d5506486ce8687586e2e28309bd60bea24aef665a5203ae3548e7be08f3581967f703c6052542c8435bb9b095240f8679bd60beafe696ab24064a186f8f20e55335cb8f17c99fdf66640b95a60ab05816d48492c9bd60bea0ea4400b1cbede9b6d100e734ca9c731309f7a7ae9ceb721e3a918843dfe404b9bd60bea30b295f6 }

condition:
	$a0
}

        