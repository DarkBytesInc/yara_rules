rule Win_Worm_Alcaul_17
{
strings:
	$a0 = { 72006d002e004a0061006e00690073005200750063006b0065006e00620072006f00640049004900200062007900200061006c0063006f007000610075006c0000000000ffffffff000000005c154000ffffffff0000000080224000000000000000000000000000ffff }

condition:
	$a0
}

        