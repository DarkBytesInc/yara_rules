rule Win_Downloader_Swizzor_398
{
strings:
	$a0 = { ddca65fdcdcbae173086013f11820ff3c2a908078519c588497e0f063f2076426d7d165c1ea0dd8637cb1dcf63452c8fb91997901b72bd28447a7b94e455ade906fdcfb7546a4e2e0ddf8ffa7e908fd61e73dc27daa4f19221a5 }

condition:
	$a0
}

        
