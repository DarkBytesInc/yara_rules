rule Js_Trojan_Obfus_132
{
strings:
	$a0 = { 7b613d285b5d5b2270757368225d2b226122292e73756273747228312c34293b763d2266726f6d63686172636f6465223b653d77696e646f775b226576616c225d3b7d28293b633d }

condition:
	$a0
}

        