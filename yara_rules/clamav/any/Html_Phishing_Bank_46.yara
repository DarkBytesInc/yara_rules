rule Html_Phishing_Bank_46
{
strings:
	$a0 = { 6d756c7469706c652070617373776f7264206661696c7572657320776572652070726573656e74206265666f726520746865206c6f676f6e732e207765206e6f77206e65656420796f7520746f2072652d636f6e6669726d20796f7572206163636f756e7420696e666f726d6174696f6e20746f2075732e2069662074686973206973206e6f7420636f6d706c65746564206279203c623e }

condition:
	$a0
}

        