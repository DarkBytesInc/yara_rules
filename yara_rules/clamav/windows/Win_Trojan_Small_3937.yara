rule Win_Trojan_Small_3937
{
strings:
	$a0 = { 495f5fdc9b530c0c35a009a02aa7a04aaf4e1f5fd61aabd21aa30cd46aef4e1f5f0fd21aab0f374c5f5f7fa02aa7981aa35b5f5f5fa0896602ab2b7dde22ab975f5f5f2b46de22abcb5e5f5f50db715c5f5f981aaf5e5f5f5fb67d5c5f5fd21aa30c0f0c3568d602a3a0 }

condition:
	$a0
}

        
