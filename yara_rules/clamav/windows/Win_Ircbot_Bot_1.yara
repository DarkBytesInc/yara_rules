rule Win_Ircbot_Bot_1
{
strings:
	$a0 = { 52554e46932fc4040477152e11df0f8997687dc418c5db74353c55128aa81c5860515549549dca1939409f14c8ec }

condition:
	$a0
}

        
