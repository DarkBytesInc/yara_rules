rule Win_Trojan_Bancos_952
{
strings:
	$a0 = { 7dabdf2f42bcc4b14fc9e025d55181540094fabdc6d143a0a98e74cfadc6ea84a846bf9980833fd2cbfd1ab3f0f8df4f1ce3d9204de6fd728ec8e25b1c16f06719d50c272a54b7283215072f2a353842107ee031491e43b4 }

condition:
	$a0
}

        
