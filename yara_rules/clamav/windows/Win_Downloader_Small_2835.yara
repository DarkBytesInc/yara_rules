rule Win_Downloader_Small_2835
{
strings:
	$a0 = { 6ce424a6fee0a5f9319164d7601de4ebb10b2b58119b6e115a3dc7a2d5c0fb3ac7ad22cde42dd64edd761e5707ee5027c06a51bcf044f88b1a8f0290bb01fd2c65dd74fb0110be47ba00311299063c60004c927ec357fbaadf89a650aa389d430ad9dbc5ff8c458adca07e739a3776bed08b }

condition:
	$a0
}

        
