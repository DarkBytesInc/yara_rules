rule Win_Downloader_Banload_607
{
strings:
	$a0 = { d377561f6d97e584d6c4c1b2df4e50446a3c4fb23c01a63d1e5b0fec3f26e208742b03eaf97c28c6796eb58a36d9e81a4ab3127b6f6ef7ef699ab062f1886dd072df761f152b0421e7f74f5718ae9fd14eecd8f0f7184aae64047cc8d55bee2a9ae7e0d625b671cc8895 }

condition:
	$a0
}

        
