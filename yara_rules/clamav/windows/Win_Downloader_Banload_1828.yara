rule Win_Downloader_Banload_1828
{
strings:
	$a0 = { eb411baae5acf90923ec2782a7a48b14166c4bd8fa097430dad46796d52e5333f95bf022f0489cfa003a844ed87b7e2d9b77d072ebb20edfd66b9972416e02bb4c8dfe04cc27e13cff387ffa99e0b2084e77dcd4da6891ab16906db64f395c8ec9cec803b874b72dce }

condition:
	$a0
}

        
