rule Html_Phishing_Bank_474
{
strings:
	$a0 = { 746f206c6f6720696e746f20796f7572206163636f756e7420616e642076657269667920796f7572206163636f756e742061637469766974792c20636c69636b2068657265 }

condition:
	$a0
}

        