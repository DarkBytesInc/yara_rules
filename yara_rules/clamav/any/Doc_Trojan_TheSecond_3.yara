rule Doc_Trojan_TheSecond_3
{
strings:
	$a0 = { 466f72596f75203d20225761697420666f72207468652066757475726520576f72642d457863656c2072656c656173652122 }

condition:
	$a0
}

        