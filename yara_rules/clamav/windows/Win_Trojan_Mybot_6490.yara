rule Win_Trojan_Mybot_6490
{
strings:
	$a0 = { a4dda93aad6ae2b520398f5f877bfd0fee106c3acbe21a0d1ba888fff91f3a49c7448128fd1df7f7f1b8a07709a1ceb5c61c8427b000a223fea5331e7edb38b9af53c31e45efd928e25b9b9aad7ebfd36632c4f5ab765f312c923cec5eb0e2fe9435cdcc0eb031065ad7eaf806b007cf }

condition:
	$a0
}

        
