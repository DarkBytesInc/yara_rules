rule Email_Phishing_Bank_1469
{
strings:
	$a0 = { 5065722076697375616c697a7a61726520696c2074756f206d657373616767696f2c20766920696e76697469616d6f20612073636172696361726520696c206d6f64756c6f20616c6c656761746f20612071756573746f206d657373616767696f20652061707269726c6f20696e20756e2062726f7773657220776562 }

condition:
	$a0
}

        