rule Win_Trojan_Mybot_8401
{
strings:
	$a0 = { 83c22aed0bf67126b4cc3c5ed92c2f21575d94cba28807ee6ffa9706be9f70938cbda73090e6ed1e38300c9b2bb5aa5dd408148c265cac4407815f9c6e62a8ec2bee342b886ffd63975b2f9cde538899c13553835a }

condition:
	$a0
}

        
