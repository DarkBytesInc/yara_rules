rule Win_Trojan_Mybot_8483
{
strings:
	$a0 = { 296fc4fe66bf72c0ed63d979d51ddc73d7bd9597fcfc6a90159f3803025ab97f596f56a355d2485abcfe17812d4ee47ab0518f2b50949bcf3f243b31586deda93d7f6d17d48d15cffd98e967e2ae5bb6981621c55e }

condition:
	$a0
}

        
