rule Win_Trojan_Servu_65
{
strings:
	$a0 = { a9718a9db6342b636972c3b0b72779675601037dddf764f604490178ade7f2e16f733b85fe17336432e58073bceec8dbc641bdb760b6b20dfc6c82a401bd7341ab911e73992454c01b6e49143046b7244132035324053240a992450c01530fc298b5e5e65bce77fffffd5ef9e79f3cf9f3efcfbf3df7dfbefb3327f09993cfdf8ee3b88f5bc12aa7272cd66b }

condition:
	$a0
}

        