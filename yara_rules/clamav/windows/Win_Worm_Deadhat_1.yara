rule Win_Worm_Deadhat_1
{
strings:
	$a0 = { e5cfafe965e284f16080cc7d1a243fe54d036ca9c23ce6b81e8155b4a9aeca59024f0c0a64061acfdba61f3ebaf6215fe21cdb9249871832a1861cc26b58eb198364ee4d0625d6d1cb63be2b713c9c782ab11b34af3fc97cdd841b62ac8ccc949c }

condition:
	$a0
}

        
