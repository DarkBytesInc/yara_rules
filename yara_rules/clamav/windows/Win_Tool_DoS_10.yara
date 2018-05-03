rule Win_Tool_DoS_10
{
strings:
	$a0 = { 33c05a595964891068d26040008d45e8ba02000000e8a6daffffc3e918d5ffffebeb5f5e5be882d9ffff0000ffffffff560000000d0a536d7572662076312e34205b3033204a756e }

condition:
	$a0
}

        
