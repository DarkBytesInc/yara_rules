rule Win_Trojan_Hupigon_982
{
strings:
	$a0 = { 39781126a6ac641047340f8b7856dcd0ddbd34636a4fa9b188dfe00bb33a5ff919550931d552fe4142206592837da44524a7baf0ba70d3f76eef106f04b33f66a59b22adca7f30585b84d6ae0ed13a38a80a395e176b7941b036b9edb0c60621438929a306fe8b694bf702c554207cb5f0070116e5f502eccf724f3ff742cf13b242d37bfb29041e444a0ef9243adb7b }

condition:
	$a0
}

        