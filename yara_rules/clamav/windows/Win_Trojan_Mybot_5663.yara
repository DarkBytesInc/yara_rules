rule Win_Trojan_Mybot_5663
{
strings:
	$a0 = { bc4ec7c269dacad3d60482b296228b4f76100eb3b924a6ed9f5d24810bbb8de7e579dc917d8858d62d39f8e614b06a1294438e0242e3b807a30e360caa097baf1ebd62c68fa812e5a15f01d28130c9daf0669e77ac4fde7791ba5e99ad499db876375a541636d5f53eac5d971c67c3c6513da9b2a24fd2849db21d606d297a4aa4e98655465cc80c32d32fbcd7fca2fa4469a3 }

condition:
	$a0
}

        