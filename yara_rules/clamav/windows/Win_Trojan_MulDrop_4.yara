rule Win_Trojan_MulDrop_4
{
strings:
	$a0 = { 5454e6cc14df024a82ff537573657233322e646c6c82ff7faa88616e656d006d736572762e657865dc77ffff005c00465245454d5a9000030000000403ffff0000b807ff42d9fb024004032b0e1fba0effffffff00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f7420626507fbffff2072756e20 }

condition:
	$a0
}

        