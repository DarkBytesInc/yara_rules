rule Win_Downloader_Banload_825
{
strings:
	$a0 = { 5a78a3b16cd8dc08647dab7eaeef1c0ce17729f5a5571f8912e66688947f4b4dde12893aa2500d70af112a7099cbcd91b2064980e5cc7819d8cdf65b0f1d0dae2c8d90a3670e5668f0406eedf0c58b9a15f93336cbaf786c3e9f }

condition:
	$a0
}

        
