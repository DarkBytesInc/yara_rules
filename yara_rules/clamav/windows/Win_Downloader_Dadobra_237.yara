rule Win_Downloader_Dadobra_237
{
strings:
	$a0 = { b68f867cc48d934f206aaabe673febbf9e2f1a6ff4050118a8a3db5e836d67d9c9bbd73fb1c6dbd26dd7b39a6701e3f6f3e3ac55f5fe8c4ab498688ec145a3e8d110016085a8f43113fbb741e476645af03d2211cabc5d07294666d771bd33ed74f7ea7b274dfc75e28d72d5 }

condition:
	$a0
}

        
