rule Win_Downloader_130975_1
{
strings:
	$a0 = { 5b002900000000000c000000440038007600390035003400000000001800000018003f007f00590024001400120016004300310028001a00000000001000000062006d0052004700770041006700770000000000180000004c003f004300470003002a000e001c00170031001500040000000000100000006800390052007a006900660059006b00000000001a0000004300260007005a006c005300380053001e006c0055002400 }

condition:
	$a0
}

        