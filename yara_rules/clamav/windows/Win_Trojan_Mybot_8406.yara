rule Win_Trojan_Mybot_8406
{
strings:
	$a0 = { 23f3475aba6202228945e5a3adb7024f177dbdc5318eb73ef8d2fb02e092b38095a50f6b94ab010bb9f320bf81cba21c05bf4ad8f31f219f9444a90023611f1eaa995828bce9fbcece8ea36ef42acb6f08e609679f }

condition:
	$a0
}

        
