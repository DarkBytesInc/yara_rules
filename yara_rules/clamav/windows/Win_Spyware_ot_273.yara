rule Win_Spyware_ot_273
{
strings:
	$a0 = { 140b48e7c6f4d4ce52204cfdf5476aba62da4ecdc3775160ba957af4657f28d6837d9eec786d31ff443e6bf16e2658e0d85689410c7394cfbd75466c816280a8425585749afde4ce74f770ac4160ad215fb8bef8d5662daeac397def12887844f2f27020 }

condition:
	$a0
}

        