rule Win_Trojan_Agent_36726
{
strings:
	$a0 = { 653d226576223b673d2266726f6d223b673d672b2263223b673d672b22686172636f64223b673d672b2265223b69662877696e646f775b22646f63756d656e74225d2961613d285b5d2e756e73686966742b2222293b61613d61612e73706c6974282222292e706f7028293b613d22 }

condition:
	$a0
}

        