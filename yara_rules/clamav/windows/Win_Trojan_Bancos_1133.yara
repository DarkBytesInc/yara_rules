rule Win_Trojan_Bancos_1133
{
strings:
	$a0 = { 7d25f915ee18dba9c4185b45714c0460c45fbeff7c6e8cf5b909e7d78cf68e8d39658939ed8eb1aa2fe5233e5de44cc9dd5efc82d2727a2a0c1e23838eb6dbfc90c58c84cf25434d6e2c6637da4281226ada4545a11f4b85c75ab126bcf4ad220ed93574f4cda87a8ddf8375759a2e4ded009f56596da4710eac9a2276c63f9b106573df4e6cbf5bb8e2d96daf06a993 }

condition:
	$a0
}

        