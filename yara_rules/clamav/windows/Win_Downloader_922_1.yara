rule Win_Downloader_922_1
{
strings:
	$a0 = { a85a0df00ba46c00b19707a261a683aad9bcc9dfba65406d6cd0a076d048b839a25cb07daa2a8a9eef3a04aa267f59ced6d413002dfc70c8db132a30b194f1c8f048bc6d43935673b61c3ac8ecb14d4614accabfc65ad4c313ef083f }

condition:
	$a0
}

        
