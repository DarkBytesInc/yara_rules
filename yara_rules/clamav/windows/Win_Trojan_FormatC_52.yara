rule Win_Trojan_FormatC_52
{
strings:
	$a0 = { 736574205773685368656c6c203d20577363726970742e4372656174654f626a6563742822575363726970742e5368656c6c2229[0-30]5773685368656c6c2e52756e20282273746172742e657865202f6d20666f726d617420633a2f71202f6175746f74657374202f7522 }

condition:
	$a0
}

        