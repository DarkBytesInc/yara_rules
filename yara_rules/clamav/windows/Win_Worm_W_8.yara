rule Win_Worm_W_8
{
strings:
	$a0 = { 2f4e4557532f2a687474703a2f2f7777772e73656375726974792d7761726e696e672e62697a2f706572736f6e616c362f6d616c6a6f32342f7777772e5941484f4f2e636f6d2f23687474703a2f2f6472732e7961686f6f2e636f6d2f }

condition:
	$a0
}

        