rule Win_Trojan_Mybot_7253
{
strings:
	$a0 = { 8ceacfb01472c272cb4660d0e38ceef94fd711ab597a23268c39a13bc0c11da32aa63e969ce3b196e71f13edb18d8a3051925102d0317cc65340e4de9707d75bd6c490b2f90992f3120aa681074f }

condition:
	$a0
}

        
