rule Win_Downloader_6792_1
{
strings:
	$a0 = { 2f66642f7363682e7068703f7665723d686f??00677264736673642e626174003a676c32333473680d0a }

condition:
	$a0
}

        