rule Win_Trojan_Spambot_255
{
strings:
	$a0 = { eabd0acc9d76d6204266768137ffff0ff01c3eb0f9d392b47f1ce07025db51506f38272ba0349830ffffffff705aecfde0f6829f951c9643e44d62075e8a0d453e3ea26db81de1920d385cd5ffff4bfa55561c6e20c37c9f2f4b7cb24e1de5d71c66c114ffffffffaf83046bd5f0 }

condition:
	$a0
}

        
