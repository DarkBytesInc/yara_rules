rule Win_Trojan_Mybot_7828
{
strings:
	$a0 = { 3a50ee9077776a20eeb07775883b40241a0e50eef07083a5090083bbbbb40a1def565e84f64f64bc9ec9fecdbc97bff78df39a3fbf73efbbded7d9e3fe563f57057a4287a67f70ad22413b017b942a244775644d69c42bb1f75fdcfa8915afe876b27a6be9d455a1740e33742398231416f36e12f2e5f43e5c305c2bc0 }

condition:
	$a0
}

        