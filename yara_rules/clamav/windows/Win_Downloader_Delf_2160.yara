rule Win_Downloader_Delf_2160
{
strings:
	$a0 = { 6abdf39ec2df932cf72c0ce33b37a331f041a06d1bbe62aa17bc03f4680952fb3f3ee5eb66ca015fdf61c99844b1f6a843ddf6d758feb071abc37deb43925c003b9438634ce33fd7b0df3881a2271b5f759744e8f423da55b6dc6c5a28692855aeaab418fb6dd5ec04ea21c78f1a8ef1 }

condition:
	$a0
}

        
