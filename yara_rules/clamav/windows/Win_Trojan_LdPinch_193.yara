rule Win_Trojan_LdPinch_193
{
strings:
	$a0 = { 12f44feb15b4c8979526ab0a323c0d4aa6fdbca8748d5834980ae17e8bfc5a145be2e4b7bdeb8a275f09f822260c739aecff2a9c9e5eddd13a56f5a244fde6f5f2361c3a31b225191a555b9ac1ea7878774b9e983ec8946bb2f34c1d46db821e2fd429b2647e9457ea5028821bb366e15b699b09ff00eb3da5a43b }

condition:
	$a0
}

        