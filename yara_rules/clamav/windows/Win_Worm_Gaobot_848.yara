rule Win_Worm_Gaobot_848
{
strings:
	$a0 = { dc0b0c576285abb6c955b290ea0539d871fd6bd8e563b6f703e45ed4a43a98a723dd512577674591536c6d1bd8898a61aec5dfdb46d2b40dcff4e16d5e01b058a12b4d16beb26eeccf66ddd9cec8f5f8a10694a8dd2dcd61fe0526fc2a0768fd8dc56e2ebf2207541319a017ff }

condition:
	$a0
}

        
