rule Win_Trojan_Bedep_1
{
strings:
	$a0 = { 612e646c6c0053746172744d75737456616c7565547261696c696e6700546861745265636f676e697365644f7074696f6e4865616465720057697468696e53686172654d75737454686546696c6500596f754c6561737442726f6b656e496e746f446566696e696e6700 }

condition:
	$a0
}

        