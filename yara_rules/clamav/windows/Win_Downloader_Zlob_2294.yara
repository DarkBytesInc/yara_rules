rule Win_Downloader_Zlob_2294
{
strings:
	$a0 = { 6fc7a4843e6360c6870c7baffdc61c1aac0cc879c887f16393ffd75642fe708e80383e5c36dc28fa85492c56c5ffb4d4f333cea46624ac425f4b86390e20c4676d4464f361b5fe8d4aa02dff3516c50a6c878e6bf825bba13968 }

condition:
	$a0
}

        
