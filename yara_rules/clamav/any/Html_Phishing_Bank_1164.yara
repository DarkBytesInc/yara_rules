rule Html_Phishing_Bank_1164
{
strings:
	$a0 = { 61636365737320746f206f6e6c696e652062616e6b696e672077696c6c206265207265737472696374656420696620796f75206661696c20746f20757064617465[0-7]616e642072652d636f6e6669726d20796f7572206d656d626572736869702064657461696c73 }

condition:
	$a0
}

        