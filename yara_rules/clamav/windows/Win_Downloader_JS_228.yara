rule Win_Downloader_JS_228
{
strings:
	$a0 = { 3c6966222b2272616d222b22657322[0-26]6f6f66222b222e7064222b2266[0-119]6777222b2268696368222b222e737766 }

condition:
	$a0
}

        