rule Win_Trojan_Karma_2
{
strings:
	$a0 = { 7574203d205753485368656c6c2e43726561746553686f72746375742846617665202620225c5468652057616c7275532e75726c2229 }
	$a1 = { 4d7367426f7820224d6963726f736f66742057696e646f77732053687574646f776e204572726f72222c2076624578636c616d6174696f6e2c2022426164204b61726d6122 }

condition:
	$a0 and $a1
}

        