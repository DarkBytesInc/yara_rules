rule Html_Phishing_Bank_641
{
strings:
	$a0 = { 69742068617320636f6d6520746f206f757220617474656e74696f6e207468617420796f7572206163636f756e74206e6565647320746f20626520636f6e6669726d65642064756520746f2074686520726563656e74206368616e6765732077652068617665206d61646520746f206f7572 }

condition:
	$a0
}

        