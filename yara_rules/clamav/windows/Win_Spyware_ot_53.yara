rule Win_Spyware_ot_53
{
strings:
	$a0 = { 465d9d2e34de2f4e24f04902dc01200dd26883c42424f91b102f81869240c1248c5627089cd623244d45e027b3d12c07e008e0119804a380ac45874eeb5d277be0293eff6462c6c975e4e065e0ba7746a6e00ca2e57a1892a9d1c1e461 }

condition:
	$a0
}

        