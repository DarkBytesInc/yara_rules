rule Email_Phishing_Bank_1515
{
strings:
	$a0 = { 504c45415345205649455720544845204154544143484544204c45545445522046524f4d[0-40]434f4e4345524e494e4720414e0a494e4845524954414e434520434c41494d }

condition:
	$a0
}

        