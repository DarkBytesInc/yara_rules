rule Win_Downloader_925_1
{
strings:
	$a0 = { 504a6d446f6c15ad0c293aca35d91cbd3485e9e6dad1d867505b539e62c64e25d808c0432e7401c9cb43d4b60beaf58fe5f6a84cd04d687618294b0cb5f9fc814092ceb680ed37c69705b0543ceefe3ce8cf662f1c12a65d5af2de6b }

condition:
	$a0
}

        
