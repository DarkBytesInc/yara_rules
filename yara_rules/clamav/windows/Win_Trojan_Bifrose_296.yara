rule Win_Trojan_Bifrose_296
{
strings:
	$a0 = { 03b14ebf39b4c01fe5ef62472ac58fc325a64f2450d926c1fadc504b7ae9e2c0ea90bd294969e62d3bd90a51be15b1caec4aa12f9ac3b587b15e596a398ab220035572cce6b24ffb0249dceed682a7f9466657c32e4170ff2280ae83ebe0cec23694b0254760b12f12ae3320ef6dafbc64bec1fdcdb2540b09575dc52b655f2d48a6c31e7393b6bcfe04704f }

condition:
	$a0
}

        