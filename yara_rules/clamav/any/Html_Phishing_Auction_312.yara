rule Html_Phishing_Auction_312
{
strings:
	$a0 = { 646561722065626179206d656d6265722c3c2f66[0-100]223e2d2064756520746f20726563656e74206163636f756e742074616b656f7665727320616e6420756e617574686f72697a6564206c697374696e67732c20656261792069732072657175657374696e672061206e6577206163636f756e7420766572696669636174696f6e2070726f6365647572652e2066726f6d2074 }

condition:
	$a0
}

        