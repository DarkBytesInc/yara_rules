rule Win_Trojan_Win_47
{
strings:
	$a0 = { 394d5a7527668379184072208b793c3bc7721903f9813f50450000750f66817f044c0175078b }

condition:
	$a0
}

        
