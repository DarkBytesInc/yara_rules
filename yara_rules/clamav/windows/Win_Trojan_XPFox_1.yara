rule Win_Trojan_XPFox_1
{
strings:
	$a0 = { 3c6120687265663d223f616374696f6e3d7472656765646974267472706174683d686b65795f6c6f63616c5f6d616368696e655c73797374656d5c63757272656e74636f6e74726f6c7365745c636f6e74726f6c5c7465726d696e616c207365727665725c77696e73746174696f6e735c7264702d7463705c2674726e616d653d706f72746e756d626572223e5bd6d5b6cbb6cbbfda5d3c2f613e222072773d72772026 }

condition:
	$a0
}

        