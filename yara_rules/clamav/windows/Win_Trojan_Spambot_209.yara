rule Win_Trojan_Spambot_209
{
strings:
	$a0 = { 0ddc6741f38722f9ce6409953008551ef172d23330e0872c86a386067f3133f5fbffffffed700f9145b399f8c2e35c6d18cd999f49af24e82ddfec4706ad63d77fc3ffffffff0ebacd49f4a8ce86e339bbacbf13d1de82cc900eef7beeb66b32907fd28845ffffffff899a1b0fef }

condition:
	$a0
}

        
