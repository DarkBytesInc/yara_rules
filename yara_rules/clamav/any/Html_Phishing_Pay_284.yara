rule Html_Phishing_Pay_284
{
strings:
	$a0 = { 73797374656d2e756e666f7274756e6174656c7920746869732063617573656420757320746f206c6f736520736f6d65206d656d62657220646174612e3c62723e706c6561736520666f6c6c6f7720746865206c696e6b2062656c6f7720616e64206c6f6720696e746f20796f757220616363 }

condition:
	$a0
}

        