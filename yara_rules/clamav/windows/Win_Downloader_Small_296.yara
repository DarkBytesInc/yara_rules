rule Win_Downloader_Small_296
{
strings:
	$a0 = { 1f6fe54902265c5f9661ac4414a97ff6dbfc0bf7d2cae2d2ecd7ff2bc7f3d6f5bbc37633ea1f8ad555ece58c250505572555c00ff454d5e90e4e2e763958f2eaf8ed2f2b5d4a99aaf4dadf101cfcb8fdbfd57f8e5cf44afedab51bf2cf023bd513eba5d9f6dae11aeabff7fb635641d6fbdebf0ffaabf7f4 }

condition:
	$a0
}

        
