rule Win_Trojan_Spambot_213
{
strings:
	$a0 = { 81e073505ae5a8c8104d30e6e6ccdbe643fdffffff3f5d2515bb4928eca46d96f3dcb666a049e9c432b8eafe2a7eb4bd5f29faffffff0271c71f2b2589fbed793e4e5a4eaafaf4b766e041ae4e58d11d712335ffffff7f3bb3dc31674ded3741115f6c57cd728336b984de65938f }

condition:
	$a0
}

        
