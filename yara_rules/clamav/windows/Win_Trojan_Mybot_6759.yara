rule Win_Trojan_Mybot_6759
{
strings:
	$a0 = { 981f93dd2c58fb14a770519a682f158b68a0aec64723c4cbde840742d50826ffa5aa281b0e0080b6ba52339b019ca61487319f01017c4fd3ba61c08500043f4bd582b64c16e767cb5a21e1ab21f5d4237d434ee8b76df2245c76e2868bbed341fb4f0cb5d065a339af5e4ece9a63e4707ae6181f173e700c766f26b1adbde4f22da44b51356979a657e4ccd35038026dffefd1e49396 }

condition:
	$a0
}

        