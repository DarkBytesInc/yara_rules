rule Win_Trojan_Spambot_262
{
strings:
	$a0 = { d258165ce52e5585ffffffe1a6fca41b4de3dd946af4c9857628fbf2554209b1ac2f3f8fd509ffbffaff5521c664ec8f40960ef71b6cfb7b914eed6ba0f0958719b6c154fffffff823a7a99616dd9958cf2d76bfe2e680ffb280f135b0de004eab51ffff9ffe1d5c61b030109707 }

condition:
	$a0
}

        
