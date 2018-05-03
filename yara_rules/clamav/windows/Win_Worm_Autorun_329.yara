rule Win_Worm_Autorun_329
{
strings:
	$a0 = { 5656033c2483c408c1ce45c1c6452bfee8136c0100530f03de5b324130095bea6450a1043be87532 }

condition:
	$a0
}

        
