rule Win_Trojan_Frethoq_440
{
strings:
	$a0 = { 4b6762711d686b6b636f586c19615e66676b701d59641970726619656a1d3b4e4c1e6a675d612a0a }
	$a1 = { 5a6f656056726d706666603c405236235c665e6a58706e5e60736c3e41386c70603d375538225e64656b5f5e6b6e6b3e }

condition:
	$a0 and $a1
}

        