rule Win_Trojan_Bancodor_14
{
strings:
	$a0 = { 506f7274616c2042414e434f205245414c202d2041424e20414d524f202d204d6963726f736f667420496e7465726e6574204578706c6f7265720000ffffffff330000005265616c20496e7465726e65742042616e6b696e67202d204d6963726f736f667420496e7465726e6574204578706c6f72657200ffffffff3500000043616978612045636f6ef46d696361204665646572616c }

condition:
	$a0
}

        