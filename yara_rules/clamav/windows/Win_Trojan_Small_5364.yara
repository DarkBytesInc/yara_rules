rule Win_Trojan_Small_5364
{
strings:
	$a0 = { 6a006a0a6a008b4b085166c745d80200e856feffff5a8b7b045766c1c808668945dae854feffff8945dc83c4108d7dd8eb0d90909090909090909090909090566a006a016a02e890feffff83c41085c089c60f881001000083ec0c685a890408e8e6fdffffe8d1fdffff83c40cc700000000006a10575689c3e84dfeffff83c41085c00f85b6000000e88dfdffff85c0a32c9b0408745c7e1f83ec0c56e869fdffffc7042400000000c745d400000000e836feffff83c410 }

condition:
	$a0
}

        