rule Win_Downloader_Delf_2068
{
strings:
	$a0 = { 96a1adb7ce83e505ad5bfb79bd86c19f5c97b5d26be21a39bf13d4a049f6fe4bbacd965ca417d5650de006c2eca02a787b70259a7959edeee0b1b82df8190d873a4f49775691c42c8c5dee094adc39bb762f389925d8538e39343c3016ec3faa6346da2afc8d05bf8c759ab8b9ccdbeb45def8e87d92de397bbbf5e6173ad11d }

condition:
	$a0
}

        
