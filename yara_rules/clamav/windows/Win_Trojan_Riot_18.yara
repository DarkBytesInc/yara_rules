rule Win_Trojan_Riot_18
{
strings:
	$a0 = { 52b85397cd218cd8488ed8a1030053062d40008bd8b44acd21b448bb3f00cd218ec033ffbe1001b90001f3a42d100050b8350150cb2ec606f200aab82135cd21 }

condition:
	$a0
}

        
