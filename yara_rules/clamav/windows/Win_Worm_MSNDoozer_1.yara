rule Win_Worm_MSNDoozer_1
{
strings:
	$a0 = { 4000ff2534104000ff2554114000ff25c4114000ff25d4114000ff25ac11400000006860234000e8eeffffff0000000000003000000038000000000000006c0761d226f3d7118059cadf45805340000000000000010000002d433030302d57696e646f7a650000000000ffcc310005430761d226f3d7118059cadf }

condition:
	$a0
}

        