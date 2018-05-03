rule Win_Ircbot_Kosovo_1
{
strings:
	$a0 = { 2e2e206a6f696e20236b6f736f766f206f6b203f0d0a6e353d6f6e20313a434f4e4e4543543a207b0d0a6e363d2f6a6f }

condition:
	$a0
}

        
