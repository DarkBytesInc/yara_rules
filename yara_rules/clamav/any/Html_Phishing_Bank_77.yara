rule Html_Phishing_Bank_77
{
strings:
	$a0 = { 73656375726974792073797374656d732072657175697265207468617420796f75722061746d206361726420697320636f6d70617469626c652077697468206f7572206e6577207374616e64617264732e3c62723e7468697320736563757269747920757064617465 }

condition:
	$a0
}

        