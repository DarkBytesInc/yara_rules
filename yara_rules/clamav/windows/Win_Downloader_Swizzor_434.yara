rule Win_Downloader_Swizzor_434
{
strings:
	$a0 = { d1c04134d397b5f33e4341f2df07ab458bbe042d32ed230945cd6fef6b2071e49e49d656b8733a7acb13f56cba6c2e2ac86f484f242fbd6d392d8589cab43ffb17053123a8f0b0ecf65b59af6f6cffba97113bbb657ac2580845 }

condition:
	$a0
}

        
