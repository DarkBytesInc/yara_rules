rule Win_Worm_Delf_271
{
strings:
	$a0 = { 696f2e2e2e2100000000ffffffff140000006f6b207665696f2c2074f4206e6120666974612100000000558bec6a006a0033c05568fd65440064ff30648920b910664400b201a1fc4e4400e80d044418a34c9844008d45f8e80d044854ff75f86830664400683c6644008d45fcba03000000e80d002cf8ba02000080a14c984400e80d04408433c9ba54664400a14c9844 }

condition:
	$a0
}

        