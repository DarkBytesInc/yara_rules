rule Win_Trojan_Mybot_8392
{
strings:
	$a0 = { 1bb499c50a251a1a879cb2f337736d7298c3cafdd09dcc59597ebff112ab777aed67e52b7a1881edf991e54d52b33672a589bfea7a60945750dfd7911b5ebd54dbb4aa2af0a762a429069d2b284443143c8ebdee4f }

condition:
	$a0
}

        
