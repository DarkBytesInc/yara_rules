rule Win_Trojan_Spambot_136
{
strings:
	$a0 = { f211896c8bd3deec9857f29432e3ace4cf3b3e49c54effffffff3ae220545afd55723c0121b4b163c27acf6cc1d37d1fdcd1f7d44d4f8f19bd4cff7ffdff0b8a5a3d3b0fa1ed2f0e876f47563d793e60fe5805ae6b46fc4afffffffffead9504f1b6a4e9a032508f36e018d578d0 }

condition:
	$a0
}

        
