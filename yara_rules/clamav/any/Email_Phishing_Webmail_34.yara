rule Email_Phishing_Webmail_34
{
strings:
	$a0 = { 4e69676572696120686572652077696c6c20616c6572742074686520756e697465642073746174652062757265617520616e6420616c736f20796f757220737461746520706f6c69636520696d6d6564696174656c7920796f75722066756e64206973206265656e207472616e7366657272656420746f20796f757220726563656976696e672062616e6b206163636f756e74 }

condition:
	$a0
}

        