rule Html_Phishing_Bank_134
{
strings:
	$a0 = { 6163636f756e74206973206e6f7420636f6d70726f6d697365642c2073696d706c7920766973697420746865206c696e6b2062656c6f7720746f20636f6e6669726d20796f7572206964656e7469747920617320612063617264206d656d626572206f66 }

condition:
	$a0
}

        