rule Win_Trojan_Bancos_1926
{
strings:
	$a0 = { a9a43f70bfa211de42584199bc622697cf86c77ca71aebd54b9db5fd560df1158e59661e433e1b9d11a19562ea53927f3a4a5a03ca35ed231259f5cedd1c4d7c76f367129f4da0fc07ca13b8a2eee16ec690be5644a4d7b6f7f7 }

condition:
	$a0
}

        
