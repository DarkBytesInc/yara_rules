rule Win_Trojan_Hupigon_692
{
strings:
	$a0 = { fe63f35b56b0486732b1484a02bc00f9821858ba85785cbdf98db245575e2f99cb5197ec4b94cab857df379f481a66383412e225da8c994f30713382 }

condition:
	$a0
}

        
