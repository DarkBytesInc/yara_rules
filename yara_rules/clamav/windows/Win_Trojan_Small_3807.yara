rule Win_Trojan_Small_3807
{
strings:
	$a0 = { faf0c9665b295402c3a5d826d234fcba5ea0d8abd5e4dd265b295c02cfa5d826fad0c9665b2d4c02eba5d8260af251a27f08dd265b5f0fabdde4de265b2d5402eba6d8260bf127f1d634fcc453a0d84e1bbc9826095f0fad1f84ccafdf847c235ba053a087a8d826de6051a27fe8d1265baf5c }

condition:
	$a0
}

        
