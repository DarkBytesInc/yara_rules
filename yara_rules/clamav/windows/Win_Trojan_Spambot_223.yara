rule Win_Trojan_Spambot_223
{
strings:
	$a0 = { 38584e94dc2c514776bb489e1633ffffffff5879a05fc4bc3203305db8028fc0bbce3a39ced7f1f2545971b64acebeba9cdeff7129fc9adda79ff9f4497d4dd76591bf28a7ffffff7ba10c1cb1932fafefff9c2f5600620ee14412de2968497c4a1703fcffff3f951c60925086a6 }

condition:
	$a0
}

        
