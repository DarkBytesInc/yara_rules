rule Win_Trojan_Pakes_408
{
strings:
	$a0 = { ed6ab05171c16aa534f155716a5586e86d0e96e28982da386d769a69d07850b356279074165748067a814f6eea80a87b61b65a8eb7cd51785ac3be6f3b1c53ce4e7b93946a7643e9997b823afbac618b94c64efa600c5b80add68f1c8657d641e57b3b62fbd0113d5a23666387eab3e0edb3b6c1c3ffa81416f347a979794796cbdbbad7bc759b6eb3fade71 }

condition:
	$a0
}

        