rule Email_Phishing_Bank_1494
{
strings:
	$a0 = { 496620796f7520646f206e6f74206c6f67206f6e20746f20646f776e6c6f6164207468697320736f667477617265206e6f772c2046697273206e6174696f6e616c2062616e6b2077696c6c206e6f74206265206c6961626c6520666f7220616e792074686566742074686174206d6179206f63637572206f6e20796f7572206163636f756e74 }

condition:
	$a0
}

        