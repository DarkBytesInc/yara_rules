rule Win_Trojan_IRCBot_187
{
strings:
	$a0 = { 6f603364305c95e5388b0864258d72799428c8f67cffff6f143e3676ee4e2fe04a6f57136f6f443471479aa65dd1ffd602ffe52d488010662d4cf5de675661cbcf5c }

condition:
	$a0
}

        
