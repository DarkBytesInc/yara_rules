rule Win_Trojan_Servu_106
{
strings:
	$a0 = { 162dab080e4c2776437000e801c0bb045a50a406d49592e202802d00383abf1ad26f5f661eb31d006d6851e9a795000040e3a8c411b492c37d21a6e2a2ce3989d6cd03f1b7000b800e001f003c12dafcb4c3c122bf4e636e3287b6178d9bf60500002c600f79a68ba9c9aad888f715b416809593511e7091105980c6fa85df5a9f373b45728d0b00002d4197 }

condition:
	$a0
}

        