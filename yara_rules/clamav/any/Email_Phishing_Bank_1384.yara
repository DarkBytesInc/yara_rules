rule Email_Phishing_Bank_1384
{
strings:
	$a0 = { 4175746f6d6174696320496e7374616c6c6174696f6e206661696c656420666f722042616e6b206f6620416d657269636120636572746966696361746520636f6d706f6e656e74 }

condition:
	$a0
}

        