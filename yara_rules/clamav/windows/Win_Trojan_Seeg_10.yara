rule Win_Trojan_Seeg_10
{
strings:
	$a0 = { 179c8bfc8b1d9f2bd89332c080ec7068000186c4b9040052f7e15a2bf08b052d027232c003d058585eb9c3005631144646e2fa5eeb4b }

condition:
	$a0
}

        
