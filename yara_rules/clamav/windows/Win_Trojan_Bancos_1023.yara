rule Win_Trojan_Bancos_1023
{
strings:
	$a0 = { b8b0d60cfaac9ea93935998c37dd1a167567d5cd71a5daf259f3fc4dda68e2667da01ee6984450c4855a06781634ed8082f7cec5acadb00e533cb93364904f3b8af0c10b57c80ff7add9e40e9b9ca14aa643e0ad74a380fc }

condition:
	$a0
}

        
