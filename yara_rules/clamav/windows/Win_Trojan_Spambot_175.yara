rule Win_Trojan_Spambot_175
{
strings:
	$a0 = { 4eef605dff03260eb5e35759c74b1cffe9ffff8554201939eecbd28b78de57c3bb5c08dc2e78f7ec6d4bd7e4b6ffe31fe0a86c51fdb4174b2edf7299106c6764f018ffff0ff05c2abbb7dde7efbf1f7cd5a862ca64a968800ed928c8d1eafffff5455ae66807d4f2c06795fdf3d3 }

condition:
	$a0
}

        
