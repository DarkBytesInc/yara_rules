rule Win_Worm_NetSky_1
{
strings:
	$a0 = { b800a04000681122400064ff350000000064892500000000669c605068000040008b3c248b306681c780078d74060889388b5e1050566a026880080000576a066a06566a04688008000057ffd383ee0859f3a5596683c76881c664000000f3a5ffd3588d }

condition:
	$a0
}

        