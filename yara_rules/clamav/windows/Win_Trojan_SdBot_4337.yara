rule Win_Trojan_SdBot_4337
{
strings:
	$a0 = { e54c3ea43ba1326f3face741e6e10aefa2014a48d5016a5d24ef9a19893c8982d764c9f844d744eb15595b9b6de0a880746c073245eb7b14cf6a10ef08fe84f6c4048223c78b8ad19d27f528e4bf885f4a6233c9a0ab0f95c149a0d9eb0d17c705b8823f16c4e2a2b40ba49cc04a5307bee326a4d9a4c2f7906e3af2aefb3f03cba5fe02d7f3a661b9ff8e8c3a47a37704749349 }

condition:
	$a0
}

        