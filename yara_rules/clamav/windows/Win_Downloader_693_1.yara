rule Win_Downloader_693_1
{
strings:
	$a0 = { acc3711dc79b17f3deb10b4157e020076a6e869de04738ee7d3155fe5e606bbfdf7c6711cba65bd3a3ab6f16466b69b259a8a332be816de0ee305ca3e1628f533d37232cb7c25df19ad31234aeb4d9e5ae5687212ceaaa3876 }

condition:
	$a0
}

        
