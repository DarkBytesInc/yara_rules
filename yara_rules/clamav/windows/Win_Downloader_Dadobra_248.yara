rule Win_Downloader_Dadobra_248
{
strings:
	$a0 = { bc2310ccb74da4e2e487cfc7e27113f90884d02cd8ad63a16e8f7e43616b8d710cbc5de9a9623dadbc934d7130c09a83fa1ba579eb8c563beb81628e25dd265d0b5c9477c1a0a6f474b2e2aca766c73e840497fac3 }

condition:
	$a0
}

        
