rule Win_Downloader_Swizzor_413
{
strings:
	$a0 = { 7f3e12c368de19412958b2e6e1d4cc74c023ecc1a9ab097f54e508ba65ceba30cd23cea30b3388e3e5029fd5e564b0f48b14a2d7a63ea8315a2e27f7fbdb6268ab19895b012ccf3db89f73735a6ab4e4ee0d5abe7c473cc62abb }

condition:
	$a0
}

        
