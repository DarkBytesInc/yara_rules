rule Html_Phishing_Bank_1122
{
strings:
	$a0 = { 61746f723e3c2f686561643e3c626f64793e3c6120687265663d[0-1]687474703a2f2f[0-35]2e6d6274726164696e672e636f6d2e[0-100]3e3c696d67207372633d226369643a[0-100]2220626f726465723d[0-3]3e3c2f613e3c2f703e3c703e3c666f6e7420636f6c6f723d2223666666 }

condition:
	$a0
}

        