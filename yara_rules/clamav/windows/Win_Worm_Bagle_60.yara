rule Win_Worm_Bagle_60
{
strings:
	$a0 = { e88dfdffffe8d6feffffc3558bec837d0c017505e8ddffffffb801000000c9c20c00ff2564200010 }

condition:
	$a0
}

        
