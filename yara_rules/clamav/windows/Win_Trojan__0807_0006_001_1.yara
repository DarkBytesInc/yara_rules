rule Win_Trojan__0807_0006_001_1
{
strings:
	$a0 = { 01e93ec68607011ab440b904008d960401cd213efe864702e965ff3e80be4702027318bf000181 }

condition:
	$a0
}

        
