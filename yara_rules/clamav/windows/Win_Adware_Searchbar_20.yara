rule Win_Adware_Searchbar_20
{
strings:
	$a0 = { 673d0000260000007765626175746f7365617263680000007b38434241314234392d383134342d343732312d413742312d3634433537384339454544377d000077000000640000003f6163636f756e745f69643d0000000068 }

condition:
	$a0
}

        