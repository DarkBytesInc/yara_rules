rule Win_Trojan_OnLineGames_72
{
strings:
	$a0 = { 558bec81eca80700005356576a5c5a6683a598feffff008365fc006a655e6a74586a725b6a53596a176689853cfeffff66898d54feffff66898d58feffff6689856efeffff66898576feffff66898d7efeffff66898582feffff66898d86feffff596689 }

condition:
	$a0
}

        
