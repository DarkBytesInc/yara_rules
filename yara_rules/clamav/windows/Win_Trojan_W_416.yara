rule Win_Trojan_W_416
{
strings:
	$a0 = { 3d202f6463632073656e6420246e69636b20433a5c5370656564792121212e657865 }

condition:
	$a0
}

        