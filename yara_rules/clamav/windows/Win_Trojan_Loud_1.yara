rule Win_Trojan_Loud_1
{
strings:
	$a0 = { 74696f6e732e566972757350726f74656374696f6e203d2046616c73650d0a4e542e496e736572744c696e657320312c2022507269766174652053756220446f63756d656e745f436c6f73652829220d0a4e542e496e736572744c696e657320322c202227316e7465726e616c22 }

condition:
	$a0
}

        