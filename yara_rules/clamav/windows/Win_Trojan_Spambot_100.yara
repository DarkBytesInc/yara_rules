rule Win_Trojan_Spambot_100
{
strings:
	$a0 = { 7933418affffffff80f033fe8a959ec94bf241cbf9da51df5e560282c60f01c5a7c4e71232f93697ffffffff4aa4b04b1066d9f15d4a316d5df3ed71a26631e6d6ebde8025d60d749620c9c7ffffffffe86efe932381f6be45cc98eab6c9b69ef53b6cf805709931288e0c8c9e71 }

condition:
	$a0
}

        
