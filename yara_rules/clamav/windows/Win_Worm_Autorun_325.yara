rule Win_Worm_Autorun_325
{
strings:
	$a0 = { 6801504000e801000000c3c30d827a9dc021a0d5d68b4af3eef69e25072f004ce20b0a2d133637b3 }

condition:
	$a0
}

        
