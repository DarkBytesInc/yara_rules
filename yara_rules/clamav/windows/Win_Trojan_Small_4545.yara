rule Win_Trojan_Small_4545
{
strings:
	$a0 = { b861a140008b1068eb24000068ec24000068ed24000068eb24000068ec24000068ed240000ffd29581c5fa954000e8 }

condition:
	$a0
}

        
