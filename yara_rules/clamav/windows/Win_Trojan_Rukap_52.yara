rule Win_Trojan_Rukap_52
{
strings:
	$a0 = { 27c22e792ffd199ae6c30c0f5f3686a3f9a367f42354342660dc0ffe0080c2e42dad798f027ed63031c0fa9d4a1e3a32b18b04eb11520ef2b33add2171cef0db86d83139e9530998 }

condition:
	$a0
}

        
