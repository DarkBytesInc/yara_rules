rule Win_Downloader_Banload_1544
{
strings:
	$a0 = { 13dbf5a30fc6cd9e3a92788fb412a607e70a76a0382718716d68e4c8b84850240b7ed90d33b60f67c4a3f007b01bffe1733916d0724378c89186f2be018952c4f00717d628c916c1cddcbe744a9edebf433f298af910b24d189a }

condition:
	$a0
}

        