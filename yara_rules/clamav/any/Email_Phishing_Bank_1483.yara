rule Email_Phishing_Bank_1483
{
strings:
	$a0 = { 436c69636b207468652022526566756e64204d65204e6f7722206c696e6b2062656c6f7720616e6420666f6c6c6f7720746865206f6e2073637265656e207374657020696e206f7264657220746f20686176652075732070726f6365737320796f75722072657175657374 }

condition:
	$a0
}

        