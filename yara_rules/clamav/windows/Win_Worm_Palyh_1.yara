rule Win_Worm_Palyh_1
{
strings:
	$a0 = { b7496d706f7274616e6365076f05e8ff4f75746c6f6f6b20457870c947362e30fea35cf7302e3236 }

condition:
	$a0
}

        
