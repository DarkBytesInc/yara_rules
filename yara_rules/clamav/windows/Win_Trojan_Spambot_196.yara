rule Win_Trojan_Spambot_196
{
strings:
	$a0 = { c0f0d06fbb9b5fffefffff9cd674a6b600462336b48ef0db5c86751505833f30d99550a9ecaa6b0cffffffffa1cdfd36a282ef4b04cd223bce602db7cb2f8f867d5f4d6fcaa3c2efd446783effffff8f8af7ae86917577f345d1af176d38943264c28d3ab4fcdf8e5c9fffffffff }

condition:
	$a0
}

        
