rule Win_Trojan_Agent_35176
{
strings:
	$a0 = { 9cf7da33cb87d9e80000000058418bf081e84e1001005047f981c637000000f7d93ac2555b6800000000 }

condition:
	$a0
}

        
