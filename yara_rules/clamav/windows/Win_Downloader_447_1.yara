rule Win_Downloader_447_1
{
strings:
	$a0 = { ff8a85a2feffff8885c3feffff80ea1080c20b8b85befeffff8985a3feffff80f568d1a5a3feffff8bbdd5feffff03bda3feffff8a078885b4feffff80c1398b85befeffff8985b9feffff80ed49d1a5b9feffff8a45eb8885d0feffffb1ee8a85a7feffff0085d0fe }

condition:
	$a0
}

        
