rule Win_Worm_CA_2_1
{
strings:
	$a0 = { 965ba79213a00ef357d9f26aaf4160de1d045680f7aac01d1b295039b07f955d22f935cb0cd41868a72492fa7fcc155736da6a977da3686cda9b2e4b72e7874a2a7150567397d550e9bd3189b050751818484d36bd89bf1d494f92ff7f0a7924df5b806d273b11005fa20552e36f0791 }

condition:
	$a0
}

        