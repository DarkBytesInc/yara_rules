rule Win_Spyware_WOW_20
{
strings:
	$a0 = { e1251dd03ef4a7c5bce01b191f8d3a836ee9459f7f249b031e3404f8579906ca483b7577613b1d6f4845f6ea683f37c6d92f4ceceefe381df7d5586d9df8f5d9d4fbce4d29c9830fcc9b541bfcacf442fc6d4ef21eb3953dcca5e649cbd1ad43f36950f3e1e0a6842b7529392ad2 }

condition:
	$a0
}

        
