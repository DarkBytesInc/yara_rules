rule Html_Phishing_Bank_876
{
strings:
	$a0 = { 636c69636b206f6e207468652062616e6b2075726c2062656c6f7720746f2075706461746520796f7572206163636f756e7420696e666f726d6174696f6e2e6d61696c2075732066726f6d20796f757220736563757265642062616e6b696e672073656374696f6e20696620796f7520686176 }

condition:
	$a0
}

        