rule Win_Trojan_SdBot_2829
{
strings:
	$a0 = { befc3e4cb84fe819956072e8546ad8628641431208b085f0f686f857a9e62d07aaac63170b79561d7f81687ff579886e02998a63b1af8be9f21adacbe00a304b85184db1234b9f2ad2ac6c51308a7f586e8ee1365ea8d7364d0042a9517a6b938c8077871f76fa402532183605107fa09aab7aa927dfc85456c6d363ac18f2aab85700fb2a1a0f97721264294bce0d52235ea523f96d }

condition:
	$a0
}

        