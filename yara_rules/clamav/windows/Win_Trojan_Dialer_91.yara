rule Win_Trojan_Dialer_91
{
strings:
	$a0 = { 0a5432d3adebf8300eb58f796c74bacdb18cad90072c2066c041090b8d24c00f7076151d600987915ade1209e477a74e5445585553c4b611120c20c4014e37a3513df12e5af7f14e2d58729b0d1163b60aaf }

condition:
	$a0
}

        