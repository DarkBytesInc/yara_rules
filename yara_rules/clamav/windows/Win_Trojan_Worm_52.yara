rule Win_Trojan_Worm_52
{
strings:
	$a0 = { 42f4e1f05f98a0fdde41cb18ea76f0f429ff307a1fbb622db5eb1c1133076903d606a23032ba2d6d94305d178eb4e6db995c50df0d8156665a764849862235f56781b970a5cfa628cd0dbc92bfb06dff29fbcfeeed9f407eae57e6e55fe8a9c0 }

condition:
	$a0
}

        
