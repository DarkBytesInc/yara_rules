rule Html_Phishing_Bank_897
{
strings:
	$a0 = { 6d7573742061736b20796f7520746f2070726f7669646520757320696e666f726d6174696f6e2061626f757420796f757273656c6620616e6420796f757220637265646974206361726420616e6420796f75722062616e6b206163636f756e742e3c2f623e3c623e64756520746f20636f6e6669726d20796f7572206f6e6c696e652062616e6b696e672064657461696c73 }

condition:
	$a0
}

        