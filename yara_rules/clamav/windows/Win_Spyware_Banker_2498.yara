rule Win_Spyware_Banker_2498
{
strings:
	$a0 = { 0d723a70ccf80d55962a565ebf641987910560e89438e6255fa06bd489ff3311b3a6e4c7e222905c8acf0991a6b81afa7aace7708b2fa734443c45245b4fc8a8da8bae6397977e9220f85b3c6a498a0a4c5e1ed944c76901eace1dd18839d1716a42a0267312a8394379e8dafb4f41bd54301eee3446e2991c7fecb7b0078ecc0eb3423c38ea1a58a676c0da44fb539169e9f4abd7f0 }

condition:
	$a0
}

        