rule Html_Phishing_Bank_774
{
strings:
	$a0 = { 647520686173742065696e65206e65756520616e7a6569676520766f6e206879706f76657265696e7362616e6b2e206269747465206c6f676f6e2c207a756d206465696e6572206e6575656e20616e7a65696765207a75206c6573656e2e2064696573657320656d61696c20777572646520766f6e }

condition:
	$a0
}

        