rule Win_Worm_Zwur_1
{
strings:
	$a0 = { 706e67e073bf2fc0f70e00347ff2b9d77d0790270608032f0133c8900c342494f507362c312f4c010400d87f4063ce0f4602467b0000520d0153ff6567004164776172f707ffff9001e62fb3e511cd818943beb0c20229b15affff2383660722627f481332b947a41e3c9f3f57d00590a0ffffa2c39bbb8d3e384fb4a77b2855b6e1b12a26ffff20b11c002e3dfbfcfaa06810a73808 }

condition:
	$a0
}

        