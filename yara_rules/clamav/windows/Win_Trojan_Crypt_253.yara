rule Win_Trojan_Crypt_253
{
strings:
	$a0 = { 5c617373756e746f2e747874[0-12]5c6d61736b2e747874[0-12]5c757365722e747874 }
	$a1 = { 6f205350414d2042746e2055 }

condition:
	$a0 and $a1
}

        
