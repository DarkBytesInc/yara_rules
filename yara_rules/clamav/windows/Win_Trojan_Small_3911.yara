rule Win_Trojan_Small_3911
{
strings:
	$a0 = { ec845b66d2c29e5b68baa6b9f10fe394e5c25a78bf11515fbf24eaaa6730ef597d9af79a683ddf5af1ffeecf70eda646b03d34636712e6d074113db26730ef597d42f79a68451cd378fae6e540f6c5cf7db95c67bf }

condition:
	$a0
}

        
