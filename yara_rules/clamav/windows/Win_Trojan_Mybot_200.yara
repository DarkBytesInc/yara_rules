rule Win_Trojan_Mybot_200
{
strings:
	$a0 = { 8d44333c52911a7df797826d7cb200524156454e534849ea4c5c442c79528641626f7766ee78e849d902ab76be5cac682e121e325a57 }

condition:
	$a0
}

        
