rule Win_Trojan_Mybot_4380
{
strings:
	$a0 = { 4f504552702e7638eb2877756e0e778220a41ce4743b0f4952434f4f00746f72adf0060ce155530244391033f7f0ba0146c171706179e0fc42820a035913169c1f4c80f884d02e636f746d14434f02 }

condition:
	$a0
}

        