rule Win_Spyware_Goldun_115
{
strings:
	$a0 = { c36421e1d2cfe258406103c16c06db3cddc7a88dfec33c626f6479b467332223fabb13ff3030323134302220c80e62316462646422d63ed48c58f322331d2d6d6b731f464632001e70957845d4ad46fd7620312e352023d765200ff5c0665e383522a5200fb66dad45d73d2065342300485456e2eded54502f3b3020327e204f4b4101bcf7f2 }

condition:
	$a0
}

        