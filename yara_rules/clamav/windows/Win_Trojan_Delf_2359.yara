rule Win_Trojan_Delf_2359
{
strings:
	$a0 = { 6801f04b00e801000000c3c370259bef5d98fa22b0637d4a7ee25b3bff00605d62890b1b7520ba52e69d954ecfc453ff42573d570e4b3e09e61e2782be5ad8a400037c77b4b3d16dead285949e1d0de9b392f781e3d807282545f95f1fa7d6a4d1153e1d717516a08756710fe4999fd17874af3f01aa10f81bbf2e90ff41951e }

condition:
	$a0
}

        