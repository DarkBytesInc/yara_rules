rule Win_Spyware_Banker_3461
{
strings:
	$a0 = { 2ec312d37f42c50d980656127d44cdad556484e3fb06da9f22eca9ba574a41e66ea8b08b2b22016a4a38e0c5724af9d6be9efe04751de3e041b8573755dddaa3eadc03efaa014bc39c7cd62712ff6c5e008f54abd7d95c8c375207ae6c5739 }

condition:
	$a0
}

        
