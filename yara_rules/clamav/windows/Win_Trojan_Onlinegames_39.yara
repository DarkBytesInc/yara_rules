rule Win_Trojan_Onlinegames_39
{
strings:
	$a0 = { 8d4dfc515753505757ff750cff1588304000f7d81bc0405f5e5bc9c3558becb820110000e8a8010000535657be04cd40008dbde0feffff6a3da5a5a566a5a45933c08dbdeffeffffbef8cc4000f3ab56aaff15903040008bf885ff897dfc751456ff15a4 }

condition:
	$a0
}

        
