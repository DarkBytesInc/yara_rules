rule Win_Trojan_Bypass_2
{
strings:
	$a0 = { 6966202877696e646f772e53796d5265616c57696e4f70656e297b77696e646f772e6f70656e203d2053796d5265616c57696e4f70656e3b7d0a2f2f6966202877696e646f772e4e535f41637475616c4f70656e29207b77696e646f772e6f70656e203d204e535f41637475616c4f70656e3b7d0a6576616c28226966202877696e64222b226f772e53796d5265222b22616c57696e4f70656e }

condition:
	$a0
}

        