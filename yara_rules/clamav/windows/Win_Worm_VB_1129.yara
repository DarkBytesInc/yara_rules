rule Win_Worm_VB_1129
{
strings:
	$a0 = { 300000004800000000000000b86c53a328be1f45a15ced0963bb0f7e00000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000980000000000000002000000040000008b48a87366efa8488d4ba04cceb79fbb01000000a8000000b8000000010000004144424501202d4533370000313144322d384132??????????????????????3100427d23f9251e8ba5f4e6488c8adfe717d1175188aa4a3c9b332946a7ded686ebf55d5706000000083840005642352136262a00 }

condition:
	$a0
}

        