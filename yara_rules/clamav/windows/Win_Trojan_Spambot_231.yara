rule Win_Trojan_Spambot_231
{
strings:
	$a0 = { e0a49da789caaf7ed051630271af94a2123384930f372b8f57ffffff2bc9edf6b43e5b2a743a0a6941cc781b9ba33e0bc42fd2b03b34ffffffffc463700391b5533702bfbf55fba820923a2f399a6c8023a39eb8bd14561eb1b2bc097cf8e9813027bb87fb5a55ff7f801fabef8b }

condition:
	$a0
}

        
