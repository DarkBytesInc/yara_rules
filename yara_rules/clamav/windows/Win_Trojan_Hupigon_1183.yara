rule Win_Trojan_Hupigon_1183
{
strings:
	$a0 = { 86c113ae2d885f9ee34dd519fb4779520f9baca0d260ed0adbd3d1b38b070c98835684883a1cc8d9a880664528598859e9b037736d9415a48a1ae632c4581fc253ed81aa1860cca272798519370ffb234e0efb855d089c7eafa79e8d78a3dd53411632d2546d21938c3a10460046088af68028c682e4dc196c2efd0a6df28a5d66cbeaff3c0d8d525b7a9060 }

condition:
	$a0
}

        