rule Win_Trojan_Spambot_239
{
strings:
	$a0 = { 96448bb5d1041b7fb8a4fc868e4effffffaf076533156eb80e6e32e593f8ff6321d825c708faef06c38dc6da1f4afad54bc5ab7ff6fe460b791c97ffffffffee1020b5061eb1600817f332521f3b283701345b7a2a20bc1defc7dc1b4c0502ffffffff3baa5cb3a7f9d9e308f39d }

condition:
	$a0
}

        
