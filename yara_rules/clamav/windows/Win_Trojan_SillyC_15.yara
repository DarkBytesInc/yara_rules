rule Win_Trojan_SillyC_15
{
strings:
	$a0 = { e90000be000156565fe800005e83c659905632c9a5a48bd65e4880c44fcd2172378bfeb43ee83100b43fe82500803de974e8b8024233c999cd212d030083c7088905b4 }

condition:
	$a0
}

        