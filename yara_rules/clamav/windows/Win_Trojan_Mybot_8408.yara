rule Win_Trojan_Mybot_8408
{
strings:
	$a0 = { cbbfefeef09ebfcbe06ab98ba6e2fddde36e106b84bf1b84807dc384edc219c65a9c80ae310ad91d6843e70d30f697072ba2a3f66a269e14042b1a150e39d60c54f4d0ac5aa2914d96014b1b7c1d04c59567667a5c }

condition:
	$a0
}

        
