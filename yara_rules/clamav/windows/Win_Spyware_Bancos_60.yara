rule Win_Spyware_Bancos_60
{
strings:
	$a0 = { 6f7374646c6c6c33322e657865ff4d73674c6173743d546865206f7065726174696f6e206e6f7420737570706f7274656420666f722074686973206f626a6563745c6e5c6e54727920646f776e6c6f616420616761696e00100100de030100789cecb9695453c9d7377a9293e4242470c218 }

condition:
	$a0
}

        