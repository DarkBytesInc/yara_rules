rule Win_Downloader_Swizzor_414
{
strings:
	$a0 = { 44e691ad23f769de0bf82b0ea5b7855c7ac7b90f8c9f53b9d648086f45a814e2c431ad4b75fc19b5ae45d7617985a6597968320bab62f88296edc3112ed1be10a6d6aada649f8dff7c79463d4dadf2a73d74fc887fba5c31a0c4 }

condition:
	$a0
}

        
