rule Win_Downloader_Small_2706
{
strings:
	$a0 = { a80c73761d63686f60fe78e420ad26124ee21692b37638571e4f49147422754a52c4cca8a99dfb7ffdfe56fd1c73f11b44532e7c0f7aac313f4f70fa7955386c41297112cc1e68fbfbc13a2f }

condition:
	$a0
}

        
