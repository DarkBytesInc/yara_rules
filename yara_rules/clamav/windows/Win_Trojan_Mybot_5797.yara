rule Win_Trojan_Mybot_5797
{
strings:
	$a0 = { fac238cedfedfc52426b55a5df7bcfad77fce61c3cf4c27a955f16149fe56d3eab4936f23f284c9447192b50631349fd6719af71bc84461add48217e5bf10c5b6017be8af6d315fa96001c54a286c34735f182f27a0f7cf43e03ac4e952d3385ecb017b55a2953018dcc42d79bc961974915f6370a3cc3b29c4df9ff939529022a39a74b9edbf411e0174050ba068c515e }

condition:
	$a0
}

        