rule Xls_Trojan_SpellChecker_1
{
strings:
	$a0 = { 4170706c69636174696f6e2e4f6e54696d65204e6f77202b2054696d6556616c7565282230303a30333a303022292c20225350454c4c434b2e584c41215061796c6f616422 }

condition:
	$a0
}

        