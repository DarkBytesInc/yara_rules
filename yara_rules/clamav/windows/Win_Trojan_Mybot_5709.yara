rule Win_Trojan_Mybot_5709
{
strings:
	$a0 = { ec79d2e0947aa2ff64283d6e66964392f85c66876a2e97ff2826ff5a0cf6fce0166beeffaa3f148de0021b95eddbe20e54ffb8afa77989ce0a73fff5a53c057b43e4adff10a3c7074468a26aff912b109394374cd7ffb3b19eb5 }

condition:
	$a0
}

        
