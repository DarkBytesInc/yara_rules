rule Html_Phishing_Pay_157
{
strings:
	$a0 = { 696e206f7264657220746f2073656375726520796f7572206163636f756e7420616e6420717569636b6c7920726573746f72652066756c6c206163636573732c7765206d6179207265717569726520736f6d6520737065636966696320696e666f726d6174696f6e2066726f6d20796f7520666f722074686520666f6c6c6f77696e6720726561736f6e }

condition:
	$a0
}

        