rule Win_Trojan_Beachwatch_1
{
strings:
	$a0 = { 500072006f0063006d006f006e0020004400650074006500630074006500640021000000140000007200650067006d006f006e002e0065007800650000000000200000005200650067006d006f006e002000440065007400650063007400650064002100000000001a00000077007300630072006900700074002e007300680065006c006c00000008000000740065006d00700000000000120000005c004d0065006c0074002e00620061007400000012 }

condition:
	$a0
}

        