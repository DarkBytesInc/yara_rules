rule Win_Spyware_Banker_1139
{
strings:
	$a0 = { d471c3ab05013a0fd9a9905a63ef9eb8ccaabeebda050ba8791b50969f5181d299a80313f6cae11007e62a0c5681ba01129988fd9c1690e047f30e10e23fd409e1d0065da9be65e4c22d77fff35207fc7c6d3fba0a03dabefc09 }

condition:
	$a0
}

        
