rule Email_Phishing_Bank_1366
{
strings:
	$a0 = { 6f6e6c696e652062616e6b696e67206861766520757067726164652c206e6577207365637572697479[0-3]666163696c697469657320666f723c42523e616c6c2074686520637573746f6d657273 }

condition:
	$a0
}

        