rule Win_Downloader_1057_1
{
strings:
	$a0 = { 43d4d410a8b697ab666e3172e1f62899b3f6fba3baf65835564dafaf98ea18c5c8b0aaeea7f6b6b1201ef1b82f83a0ed6da139d91ab9b5621759098c00989ab66a3312b1a21250473db16caa9120b6a6b4aead886c8ec6ccb13d7fb7 }

condition:
	$a0
}

        
