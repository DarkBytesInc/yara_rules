rule Html_Phishing_Bank_762
{
strings:
	$a0 = { 6920616d20736f72727920746f2061647669736520796f752074686174207765206861766520626c6f636b656420796f7572206f6e6c696e652062616e6b696e67206163636573732064756520746f20736f6d65206972726567756c6172206163746976 }
	$a1 = { 656c70696e67207573206d61696e7461696e20746865207072697661637920616e64207365637572697479 }

condition:
	$a0 and $a1
}

        