rule Win_Downloader_Delf_2159
{
strings:
	$a0 = { 5aba2c9b34d20682ff2286da1a686aca1f2e2a82dafd1cac99be8c53e93ac2d141706abdf39ec2df932cf72c0ce33b37a331f041a06d1bbe62aa17bc03f4680952fb3f3ee5eb66ca015fdf61c99844b1f6a843ddf6d758feb071abc37deb43925c003b9438634ce33fd7b0df3881a227 }

condition:
	$a0
}

        
