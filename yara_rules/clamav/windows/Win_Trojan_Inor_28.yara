rule Win_Trojan_Inor_28
{
strings:
	$a0 = { 686e6166763d22736372697074222b22696e67222b222e222b2266696c222b22657379222b227374656d222b226f626a222b22656374227969637a3d227773222b226372222b226970742e222b2273222b2268656c6c22 }

condition:
	$a0
}

        