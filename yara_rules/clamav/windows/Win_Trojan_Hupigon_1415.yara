rule Win_Trojan_Hupigon_1415
{
strings:
	$a0 = { 5e2a7885c4f479f75e953f840f76afc44864ca1e8618e3cff856ab9c32075e71f4f26dca39aad99c6679e7e00281d8b6338ef279a68c6631d25aba7caaa004386969a0acbf88531fcf09191f3d19255b693d16b6e8215462eaa4f2cc8f8cf4a5a831454634d9dfe50330565e657d8c2052d6200cc7cc724f634f29837b2ad37f }

condition:
	$a0
}

        