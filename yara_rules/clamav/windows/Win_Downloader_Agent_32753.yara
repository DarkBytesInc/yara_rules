rule Win_Downloader_Agent_32753
{
strings:
	$a0 = { 0080e19655b14189e580ceec83ec245680eef65780e68a539c80ed325580f5a583ec08c70424020000808b45088944240480cdc180ee8ce80736ffff5d8945e48b45e48945e080ed0f80f6a05583ec08c70424010000808b45088944240480eeece8dd35ffff5d80f2c28945e88b45e88945dc837de000750b80cd98837ddc007502eb07b801000000eb07b800000000eb009d5b }

condition:
	$a0
}

        