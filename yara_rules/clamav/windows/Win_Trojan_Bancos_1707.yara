rule Win_Trojan_Bancos_1707
{
strings:
	$a0 = { e9f33fdbc8510efc0cddcb897f195570ea5f24df0bb6ef6c0550d5baf03cff1e8c7c113e758a72f6e0019b7b669b951e1cb5d201207778b902eacd4f2c28a70b35f0a55b75a3d517f78617182535b8ce4eb2c55b4b692bd191727f59ad89160e77b13ce9d503a7c6986312aa0052bede7a81643563a01fa8304c029532f7c51b87858bbb06317ebe8576a32b }

condition:
	$a0
}

        