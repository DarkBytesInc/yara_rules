rule Win_Downloader_Small_4897
{
strings:
	$a0 = { 410410cf30d935040099c5fba1dc0bc07402ffe068b782dec9b880112b789a25d033094b11a0ee853d555841455845c51871164355549ac7e2965c681711dc6e705864b03c2f63a2b8cfb2726fb265994f6975c8649acd6c7775c365b562762eec4964b8d1b25c692e5f0b69a62f91d362bc78739b3eb47d6ec52a8763ff18e2fb23bea9 }

condition:
	$a0
}

        