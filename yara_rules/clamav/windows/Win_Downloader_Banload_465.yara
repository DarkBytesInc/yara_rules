rule Win_Downloader_Banload_465
{
strings:
	$a0 = { 89fdb0a58f6a07d44a9b1ea37f940b22a3987ee0173df8777e88ee8a79e88b059b95aa33749a519a186db3947b74f8ebe8dc41826e6ec8a2866258464553af0a85a8c5d42515da2f0815b189fdccca6bf8c6e3ff }

condition:
	$a0
}

        
