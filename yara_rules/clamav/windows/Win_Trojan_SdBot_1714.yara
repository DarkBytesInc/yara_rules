rule Win_Trojan_SdBot_1714
{
strings:
	$a0 = { 6f49bc644a04b7640525e32f6ee0c3ea1ad852eb16e70bd92e7a1e0c9c5445ad5261f8eee7850de31e47b5e6a3507305659783499fa427a2e628653de237d2164a03bc37d5f5fd1c829f3fdf9340dfe178c50743d51c2515ebeede79fdd0ce1514a035bbe67d8dafe3d2897c76817fbdef66df89dba665df94536380ec45d00345b86511108d09a0336e1ca361a339628e065edbf4 }

condition:
	$a0
}

        