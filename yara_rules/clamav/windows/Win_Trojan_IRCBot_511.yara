rule Win_Trojan_IRCBot_511
{
strings:
	$a0 = { f98ded678499b0f5ae9ccdde89be041a37482476866e0e77aaa8129924f4679c0dde6b081d1a5ce3d01e97e1ed66a6d900868cf6a041c5470971703d0024be935b2f8b9fc63100ba5edba0df1b02652afb20c80d229eb7c8ae7147fbd400b6575379a14cc7b1d2103188bf804592dfd50e9922b9f135412068ce2bffa2e0d8cef38701ade6caddc794a96aa5f53a9c2edfbbe4da662d }

condition:
	$a0
}

        