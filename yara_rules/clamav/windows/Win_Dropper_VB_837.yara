rule Win_Dropper_VB_837
{
strings:
	$a0 = { 6bdc81970656ff0c384109e09e7ea70238f488fa4f29df317f075d2e1f7e329edecce4c03cc70a38b8d67e18b3096fc040be7a7d58d3c11fcc7ba14123f0eca07fc2aee1b10168d4c1c2e9cb3d04248d2eea878082341dc3c1f0d25a3046b674c62dcd31764ee45dfc2274c3017d88c4762c80168015ae926804d510902286ae8e00664e362682a2532b5410 }

condition:
	$a0
}

        