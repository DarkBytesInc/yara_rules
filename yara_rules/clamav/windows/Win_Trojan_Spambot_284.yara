rule Win_Trojan_Spambot_284
{
strings:
	$a0 = { 13995246c364bd3b15dcd2873bca8dfc4171b48ffeffff3d1d48d0061cfab02c5590dd02422f544602864511bc723745163f5affffa3a1f6582adbda2c2ba7be30f97ec48b6f61b013ffffffff3b6209176a12e5fc21445946ffa93a56738a561a1d55fff99d163b4d5b6366dcff }

condition:
	$a0
}

        
