rule Win_Trojan_Shell_68
{
strings:
	$a0 = { 3c3f7068700a[0-64]24636f6c6f72203d202223646635223b0a2464656661756c745f616374696f6e203d202746696c65734d616e273b0a2464656661756c745f7573655f616a6178203d20747275653b0a2464656661756c745f63686172736574203d202757696e646f77732d31323531273b0a707265675f7265706c61636528222f2e2a2f65222c22 }

condition:
	$a0
}

        