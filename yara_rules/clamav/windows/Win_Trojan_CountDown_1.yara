rule Win_Trojan_CountDown_1
{
strings:
	$a0 = { cd21909090e94301909090b44090e9e400cd219090b8024290909990908bca90909090909090e8 }

condition:
	$a0
}

        
