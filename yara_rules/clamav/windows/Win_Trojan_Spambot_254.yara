rule Win_Trojan_Spambot_254
{
strings:
	$a0 = { 5a3048eadd246c46cac6c7a6b16b6ec89bb4ffffffff06627939586ebe60f5159d77ab24f0789a523b1086f8072e8266075743d4c8aefdffffff28d648468bc68a834aec64c5f17bd584ee9a5d6a77d29a71bc53155a352effffffffade862d6e522acfa27dae205a479a0d7eeb0 }

condition:
	$a0
}

        
