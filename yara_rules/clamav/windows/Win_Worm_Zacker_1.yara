rule Win_Worm_Zacker_1
{
strings:
	$a0 = { ff1518114000c78574ffffff98504000c7856cffffff08000000c78554ffffff02000000c7854cffffff020000008d55ac52b810000000e83a2dffff }

condition:
	$a0
}

        
