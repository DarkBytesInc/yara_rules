rule Win_Trojan_VB_1367
{
strings:
	$a0 = { 2c1540000000000000000000000000002c1540000000000000000000010005003019400000000000ffffffffffffffff00000000741a400028504000020000006c1540000000000000000000000000006c1540009303000000000000010004003019400000000000ffffffffffffffff00000000441a4000585040000a000000b015400001002000000000002cc41f00ac154000fc204000750061006c002000530074007500640069006f005c0056004200390038005c00430032002e00450056423521f01f7662366368732e646c6c000000002a000000000000000000000000000a000408000000000000802a4000f416400000f0300000ffffff080000000100000000000000e90000003c1440003c14400000144000780000007e000000840000008500000000000000000000000000000000000000b9a4b3cc3100b9a4b3cc310000b9a4b3cc31000006000000a024400007000000e02340000700000098234000070000004c234000070000000423400007000000b8224000070000006c224000070000002022400007000000 }

condition:
	$a0
}

        