rule Win_Worm_Autorun_282
{
strings:
	$a0 = { 9c60e8000000005db8070000002be88db5??feffff8a063c0074128bf58db53?feffff8a063c010f8442020000c606018bd52b95c?fdffff8995c?fdffff0195f?fdffff8db5??feffff0116606a40680010000068001000006a00ff957?feffff85c00f }

condition:
	$a0
}

        
