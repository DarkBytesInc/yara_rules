rule Win_Trojan_Agent_35226
{
strings:
	$a0 = { df448c4376002cd0989c86ffbb5fcc79df107fa17826367db16a787f720bdaacbf64f96a2b5d6590c6a054b0b47df724d754394c9f2877bb9a2eaa743ea7dfbbc3c3c59047fdf31a5c632052909f0d1d4d0e5faf75bfae6cd431a1fe }

condition:
	$a0
}

        
