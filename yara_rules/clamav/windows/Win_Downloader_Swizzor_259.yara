rule Win_Downloader_Swizzor_259
{
strings:
	$a0 = { a9f1206e79a6f7a46b8f3d4585d5f5e6f60c83973fc3e0391c14cedf65ad0da8a0587cdce7c676f6e68c74c6ea48d3eeedaaaa16ace5d0dfe3b084b8c111c6452186a1fa8431baec3f442ed598114e3b7c03ff647e4aceb5930b0fe1d99f93bc34ad57b476eca57ddc1367f5ff2efee43844c49849824e6f }

condition:
	$a0
}

        
