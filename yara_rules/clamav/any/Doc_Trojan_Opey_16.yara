rule Doc_Trojan_Opey_16
{
strings:
	$a0 = { 43617365202256697275735265706f7274222c20224a695368656e68756122 }
	$a1 = { 2e5573657241646472657373203d2022bcbdc9f7bbaad2d1ceaac4fab5c4bbfac6f7b0b2d7b0c1cbb7b4baeab2a1b6beb3ccd0f228763333292ccac2c7b0ceb4d5f7c7f3c4fab5c4cdacd2e22cc7ebbcfbc1c22e22 }

condition:
	$a0 and $a1
}

        
