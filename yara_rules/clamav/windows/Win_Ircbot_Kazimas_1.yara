rule Win_Ircbot_Kazimas_1
{
strings:
	$a0 = { 6f707920633a5c77696e646f77735c6b617a696d61732e65786520633a5c6b617a696d61732e657865203e6e756c }

condition:
	$a0
}

        
