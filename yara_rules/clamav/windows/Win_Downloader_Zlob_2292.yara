rule Win_Downloader_Zlob_2292
{
strings:
	$a0 = { 3756606f6e6f79bf2c58d1cbbea49f641a52f0a78b05701683cdb16342f0ec64e549b8aa2619f4a3c51bdefd432649f652cf624b02128ffc1765b5f0bc192495b2dc7b023f14207ee994d32d529630dbd6a458cfdfdae2dc9b9e }

condition:
	$a0
}

        
