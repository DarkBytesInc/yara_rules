rule Win_Trojan_Mybot_7261
{
strings:
	$a0 = { 23a9e294532559e964c50d610b779c78264107d3a64c7f7365421a49711d2b4b19ee59980d810810395b48241c2257646614a5ac8b60b057b75e669706e7790c99180cd21ae9fee8758def80420d931fb461f51a0caff76affaccfa570e372dd0265421997ded6e47e7473a2fcdb1d31586d1457e490387b316ba69c7c92f5588b8dfe9628c4d1e4f4cb1647e6b7a6d14f9dd015c920 }

condition:
	$a0
}

        