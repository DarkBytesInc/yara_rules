rule Win_Trojan_Madtol_1
{
strings:
	$a0 = { 636f7079202f592069746e616c697370793636362e6f20433a5c52454359434c45525c532d312d352d32312d303630363938323834382d313035373930343138362d3835343234353339382d313030335c69746e616c697370793636362e6f }

condition:
	$a0
}

        