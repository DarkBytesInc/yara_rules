rule Doc_Trojan_Lily_2
{
strings:
	$a0 = { 4966204d6964286e6e2c20312c20333629203d202220202054686973446f63756d656e742e556e70726f746563742050617373776f72643a3d22205468656e }

condition:
	$a0
}

        