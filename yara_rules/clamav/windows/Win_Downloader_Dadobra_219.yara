rule Win_Downloader_Dadobra_219
{
strings:
	$a0 = { e541e4d8ceb3dc02a70c72bdd78cdf7b8d008b2e39dc515be4d6a7a594ff38e8b71e0e9c59be3b32ca8be7c63aba2f32bc3f30bec8f4121c8c2ae52fbbd74466db7af0b397ec51737942011b421f24b610dd0efd3da64f0d57fe }

condition:
	$a0
}

        
