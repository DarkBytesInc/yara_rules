rule Win_Trojan_SdBot_4054
{
strings:
	$a0 = { 6b8aa6d8c1254b032b6fadcc3acef3f26625171a0c42b3b77871aa4afc9f1f8cc30738e1fef23b33be1e15238a2c3d75fac14c317f7efbf411adbe970aa8da219ddabd79b46303bfc08baf8f2ad0348becba8e185417 }

condition:
	$a0
}

        
