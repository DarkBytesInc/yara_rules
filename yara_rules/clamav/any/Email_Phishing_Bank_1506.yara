rule Email_Phishing_Bank_1506
{
strings:
	$a0 = { 41206d65737361676520726567617264696e672022596f757220696e746572657374207261746520686173206265656e206368616e6765642e2220686173206265656e2073656e7420746f20796f757220536563757265204d6573736167652043656e7465722e2020546f2073656520796f7572206d6573736167652c206c6f67206f6e20746f }

condition:
	$a0
}

        