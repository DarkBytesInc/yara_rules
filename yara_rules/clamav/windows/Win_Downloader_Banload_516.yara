rule Win_Downloader_Banload_516
{
strings:
	$a0 = { b2626ca182144f9f75816134463941ed2de97a81cef2b6f1f6e37cc7da0468495303bfe43ae493f08477052587434fe48a76700ec33c6c79aa229a6325544cf3dc5800a88a688c963b02ca86dd2837a0f5ee159dd613c0b66b4077911e47e7c97afed7bb39f9f49eec140611db39e51ba846216028180a8b39c038d94b779fbe2607 }

condition:
	$a0
}

        