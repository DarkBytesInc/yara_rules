rule Win_Downloader_Delf_885
{
strings:
	$a0 = { 5bcda3dbbb63195ba8c83a6762b6584b7ecae3d05c1a38b01f11dfee5aba2c9b34d20682ff2286da1a686aca1f2e2a82dafd1cac99be8c53e93ac2d141706abdf39ec2df932cf72c0ce33b37a331f041a06d1bbe62aa17bc03f4680952fb3f3ee5eb66ca015fdf61c99844b1f6a843dd }

condition:
	$a0
}

        
