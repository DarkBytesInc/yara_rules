rule Win_Trojan_Spambot_253
{
strings:
	$a0 = { e4ee2d30ce2e40c1c6a269795f37df3ec77be15ea2086e8cbffaebffe7b87aaec0cef147fdd1ddabc34cf403f3124141ffffffffbc391d49d43dad97caf494054b5a03f70d59b82d4849476b0ed540f2bc701255ffffffff8a44cc640c0e65c7439dcc9013c55581b2653449684b }

condition:
	$a0
}

        
