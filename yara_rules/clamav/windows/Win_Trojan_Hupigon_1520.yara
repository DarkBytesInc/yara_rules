rule Win_Trojan_Hupigon_1520
{
strings:
	$a0 = { 3c84e01a75294d1ab80ced00105064ff35000000006489250000000033c089085045436f6d706163743200eb539ac96b5234eaac411cab4cdc2e9713480b8286a62b4298c1898acfd67fdcb3f1b76a6a65df99560b52f734589f5bff8306f6ff60f4d0962b22416b1e18a5e3d66e00f325203e2d0140b461174de60f62eebaa017c1328967ec52b322df075b }

condition:
	$a0
}

        