rule Win_Downloader_Small_1762
{
strings:
	$a0 = { 68748e703a2f236c6966371c6b52812e636fcc7a61762fe6703365748564d879352eca72663f7cf43a3d5c627b3f742e156c644b }

condition:
	$a0
}

        
