rule Html_Phishing_Bank_607
{
strings:
	$a0 = { 6e6574776f726b2e20666f7220626f74682c206f757220616e6420796f75722073656375726974792c207765206172652061736b696e6720796f7520746f20616374697661746520616e206f6e6c696e65206163636f756e74206f6e206f7572206461746162617365 }
	$a1 = { 6163636f756e7420696e20323420686f7572732061667465722061637469766174696f6e }

condition:
	$a0 and $a1
}

        