rule Win_Ircbot_Sunova_1
{
strings:
	$a0 = { 6620553f20696d20736f20686f7421212068756d6d6d203a290d0a6e32313d206f6e20313a746578743a2a656e642a3a }

condition:
	$a0
}

        