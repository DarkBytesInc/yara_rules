rule Win_Proxy_Horst_228
{
strings:
	$a0 = { 8be55dc3cccccccccccccccccccccccccccc8b542408568b7424088a0684c05774378b7c24148a0a84c9742d80f9417c0880f95a7f0380c1203c417c063c5a7f0204200fbec00fbec92bc1752e4f742e8a4601464284c075cd8a023c417c063c5a7f0204208ac88a063c417c063c5a7f0204200fbec00fbed12bc25f5ec35f33c05ec3cccccccccccccccccccccccccccccc8b542408 }

condition:
	$a0
}

        