rule Win_Trojan_Bancos_1985
{
strings:
	$a0 = { 4fbd6a59e695067d97e8c1f2fe9e41e6cda35963a16d8db47144e61bc245712550e2b5bf9d7b82c1b9ea5170023ce075490c3f5f21594c80e7d900b88e86a3e6589decb9c6e54e3d1c3f8e6784d2518d36d405121ad604294b32d00012666b15786e37e68a9285ffb5f4532538c9 }

condition:
	$a0
}

        