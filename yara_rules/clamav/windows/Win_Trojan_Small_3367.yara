rule Win_Trojan_Small_3367
{
strings:
	$a0 = { 3f39798a431c000cb5adfdb739b9383d473f003a3d40133f4204f6edf6bf3746725763585972317215726e007230616398f66feded32005535384d1e6500372e507c227c420de06fff55464f3a383243d73438313220207142b2ffff6f686e2e736f6674706c }

condition:
	$a0
}

        