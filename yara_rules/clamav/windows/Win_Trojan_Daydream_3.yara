rule Win_Trojan_Daydream_3
{
strings:
	$a0 = { 6f7729203d2022313522205468656e20447265616d203d203120456c736520447265616d203d20300d0a496620447265616d203d2031205468656e0d0a536574417474722022433a5c4d73646f732e737973222c2076624e6f726d616c0d0a53797374656d2e5072697661 }

condition:
	$a0
}

        