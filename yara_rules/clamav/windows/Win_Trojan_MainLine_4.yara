rule Win_Trojan_MainLine_4
{
strings:
	$a0 = { f31d39a3ec54048942daf776bfee9c604e83de98b7699402735e6acc67d23a8c5b2a70b1daaeabfa185232c0647be6145234ffad0adbb3e7ed6848aee7f075861929023c0aec779ec01b0f3fad95a3d89900dc1fcbc41f243f7ac3b7e7f928240a2bf5e636ac54b3b0cf0f0209afaf2f4c53bce6e5df623aaec038f989 }

condition:
	$a0
}

        
