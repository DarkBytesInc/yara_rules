rule Win_Trojan_Mybot_8380
{
strings:
	$a0 = { 5d354ea5fc452407d8ee9c0b406782be874d79fd41aa9bbeb572bf362647975e9926946a9942ba890a652f55fd00e10b953cf1c105a2a54704cda4f8b9afca5cc1f7368e01f515df2f468fc4108cbcc56dde7afa2c }

condition:
	$a0
}

        
