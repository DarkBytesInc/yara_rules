rule Win_Spyware_Banker_4575
{
strings:
	$a0 = { 1bc8ee71823ae3ef3b3cd2db72ad81e5419d9666d695bd3ab89d8bc9b23ff8e971acef63827193375e690ba7f355e4bba2e11d240aedcad58f75ce18ea546fc22fdd7dbef02c7fcdbbeef8bf685f465b47aadd90685f2c2c34dc64ee77b1c70710836ce0 }

condition:
	$a0
}

        
