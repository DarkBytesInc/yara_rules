rule Win_Trojan_Renos_21
{
strings:
	$a0 = { c283fa0076378b8518ffffffff8d18ffffff898520feffffff8538ffffff29d02b8560ffffff81f8030a0000740fff859cfeffffff85ccfeffff0945a0ff8d5cffffff8995c8feffffff8d1cfeffffff1534a24100e85649000029d2298df8feffff218d }

condition:
	$a0
}

        
