rule Html_Phishing_Bank_401
{
strings:
	$a0 = { 6265207375726520746f206c6f6720696e207365637572656c79206279206163636573696e672074686973206c696e6b2e206f6e636520796f75206c6f6720696e2c20796f752077696c6c2062652070726f7669646564207769746820737465707320746f2075706461746520796f7572206163636f756e7420616363 }

condition:
	$a0
}

        