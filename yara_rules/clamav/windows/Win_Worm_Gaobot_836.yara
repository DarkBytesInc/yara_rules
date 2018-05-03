rule Win_Worm_Gaobot_836
{
strings:
	$a0 = { 16f422d5a89d826f88dc7580efe6b1c56544e0acf094fea2c4b3ffbf1d2ca809f57cf6494183f6c75c4fdaa45a34df9f608bca394ee8815d5c4825ae4ae5331b512edf38950d38fe450116637179f9eaaff3e8b3e4ae5a94fe6ee51e1e6eb3ee379bb63271c8bf16f32ede173b }

condition:
	$a0
}

        
