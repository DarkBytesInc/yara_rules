rule Win_Trojan_Fakecodec_4
{
strings:
	$a0 = { c8898570feffffff8d78ffffff01c84883f800752f29c881e8f700000001c80b8d08feffffb9e2000000098dd0feffff01c1238d08feffff038df0fdffffff8d50feffff83e80429c92155d029d149ff8564feffff1b8de0feffff4109d121d183f90075 }

condition:
	$a0
}

        
