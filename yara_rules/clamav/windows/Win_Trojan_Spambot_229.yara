rule Win_Trojan_Spambot_229
{
strings:
	$a0 = { 43ba2200689b501147ffffffff1b945aac30eeb68998feeabc2b6d6b423b886a4f536a74faf418a61d8bb6a919ffffffff322b146d2046973c8d03cd0435d03eabbe96cda6a641bd5699e812214f95ab8819ffffffaa6f6584e527f32cbdecc5dca475a9883c16a256e02c2e0aff }

condition:
	$a0
}

        
