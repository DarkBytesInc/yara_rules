rule Win_Trojan_Agent_35136
{
strings:
	$a0 = { 9729cb64e65b68a52814d285034c6b84b701ab030f93dbdb7f677626ec5fe43b4daadf2a8fd4dca1678aa1d1ba82841eedffeb0e7052bf46f84156b3076832e196d1f9050208fad330c5a0af2c40c7c4 }

condition:
	$a0
}

        
