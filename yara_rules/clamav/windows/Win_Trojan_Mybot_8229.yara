rule Win_Trojan_Mybot_8229
{
strings:
	$a0 = { 6f515e04b0ebd21c9ce16f5762e74c84a2a3b01abc5b643646faadbadce5adfb0f515e0450ead210bee14f905759f003fc38da17a956b928a9cf9afa399dae1873531e3156c4f77169dc45605fd4c6f617eb959681af4524a7ef9af4a52a993b43a94488914c42bca2dbd4808f42dfe4b025a6fc221f4693755ce8ed29f9363443a9b02aa563320189dbc08041dbb8ea83df911ab7ad }

condition:
	$a0
}

        