rule Win_Downloader_268_2
{
strings:
	$a0 = { 14fa2e843a10d5ea179ee34b5e71d77b309b796af43372a9ff80a9d7668e6095fe6d974656805e0e796054aef1698e813b73514fcc0b4aae2608852a3c7aab155d00663b7d6c93f36a7178f0073d }

condition:
	$a0
}

        