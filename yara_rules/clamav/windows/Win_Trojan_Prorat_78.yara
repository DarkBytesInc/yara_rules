rule Win_Trojan_Prorat_78
{
strings:
	$a0 = { 43fe2ea49c6f37e5de65512ff1e39d74a691c8b59e6c33bcb81e497932b31543e2376e8c4f0d84822521b2f84c07db2dc889f41b54ea80e905ef0e3dc146f43de9f5753dd52d47c2771830e96a36124af4314e56f6d84e8d6a12707b7b3c9e7871b1f52fd3e1435d815f45daae5f411de78e6b8de286d9d2d8a7f8 }

condition:
	$a0
}

        