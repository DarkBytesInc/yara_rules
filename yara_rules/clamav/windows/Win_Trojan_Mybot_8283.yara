rule Win_Trojan_Mybot_8283
{
strings:
	$a0 = { 60000000009615d86e7db3e438ea8300fe758eaf2b78d30039cfd141b2cc2cc4006782c1a400000000b9681d100e9b9f43e8e05b469d61541fce010a808236a65ff45d3b68191fc6b60000000041cdd2e2cab2ec7cac00fe57dd171f91107a00aed06b3656edf12a00fcaf394e000000006c480633e6541473c7348a00b998d165f111e003d0e36d91052ad8 }

condition:
	$a0
}

        