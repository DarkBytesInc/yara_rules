rule Win_Trojan_Mono_6
{
strings:
	$a0 = { 908bd233c05bc39090909090558bec81ec2801000053908bd2908bc08bdb908bd2908bd28bd290908bc08bd2908bd2908bd28bd29090908bc9908bd2 }

condition:
	$a0
}

        
