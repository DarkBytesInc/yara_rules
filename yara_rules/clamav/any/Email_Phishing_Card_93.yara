rule Email_Phishing_Card_93
{
strings:
	$a0 = { 53756976657a206c612070726f63656475726520696e64697175656520706f7572206d657474726520766f7472652063617274652064652063726564697420e0206a6f75722e[0-200]6e6f7573207365726f6e7320636f6e747261696e74732064652073757370656e64726520766f74726520636172746520696e646566696e696d656e742c63617220656c6c65207065757420ea747265207574696c6973656520706f757220667261756465 }

condition:
	$a0
}

        