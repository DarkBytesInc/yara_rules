rule Win_Downloader_287_1
{
strings:
	$a0 = { 235b3b634a51684dbe73f723f53a198054a17a18b817f675747f8fcda916efcd28c8880dc2cfe87f29ad558b9d1efdbf57455e819cfbda61f1ba8d18704f0bf5b1298b4bd085d22c897851e662bd }

condition:
	$a0
}

        
