rule Email_Phishing_Bank_1236
{
strings:
	$a0 = { 4469657365732056657266616872656e20697374207a7572fc636b7a7566fc6872656e206175662065696e20526f7574696e652d42616e6b696e672d536f66747761726520616b7475616c6973696572656e }

condition:
	$a0
}

        