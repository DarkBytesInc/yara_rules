rule Win_Worm_Info_1
{
strings:
	$a0 = { 0b61e681fc2833671e9f4205594fceb2fa89086e80b1a3bb06810fc3401ca26d5b83aec34b7abcd10b26dcf1c95c24f34b6dbcf71394f7a757fb8943994e4cef1e2826cbbab99ee2442906f036218686664752e1bff70e6f5a29eb3c455ecd5ce7bf4b6cbe458fe0620c448dc3a6a42b88ce7a3354c9b6eb207303a1 }

condition:
	$a0
}

        