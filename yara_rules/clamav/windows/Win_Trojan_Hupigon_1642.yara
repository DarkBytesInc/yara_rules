rule Win_Trojan_Hupigon_1642
{
strings:
	$a0 = { b6d795f38b93b5acfe80cf556257d2a983ea2d5ecac37df77e7c1b1de6b3a4039810d0043f9caa3713895c0645d9d24e08b9bc0148dd1abd19b8013f8c13241b19abd4fd391264efd7ceac0f775e38a6c5e1cbeb5b64d30b8a02 }

condition:
	$a0
}

        
