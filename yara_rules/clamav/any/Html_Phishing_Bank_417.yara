rule Html_Phishing_Bank_417
{
strings:
	$a0 = { 696620796f752063686f6f736520746f2069676e6f7265206f757220726571756573742c20796f75206c65617665207573206e6f2063686f69??652062757420746f2074656d706f72616c792073757370656e64206f722064656c6574656420796f7572206163636f756e742e }

condition:
	$a0
}

        