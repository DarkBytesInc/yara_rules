rule Win_Trojan_Crypt_184
{
strings:
	$a0 = { bd92484300c74500d4003e00b86eb93e0089450489455850c7451089250300ff4d0cff4514ff455cc645 }

condition:
	$a0
}

        
