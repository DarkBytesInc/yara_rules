rule Html_Phishing_Auction_141
{
strings:
	$a0 = { 64656172206d656d6265722c3c62723e3c62723e3c2f74643e3c2f74723e3c74723e3c74643e65626179206d656d62657220[0-50]2068617320696e646963617465642074686174207468657920616c7265616479207061696420666f72206974656d2023 }

condition:
	$a0
}

        