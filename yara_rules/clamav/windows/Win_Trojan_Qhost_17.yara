rule Win_Trojan_Qhost_17
{
strings:
	$a0 = { 32372e302e302e31207777772e7472656e646d6963726f2e636f6d0d0a3132372e302e302e31207777772e677269736f66742e636f6d0d0a3132372e302e302e3120646f776e6c6f6164732d7573312e6b6173706572736b792d6c6162732e636f6d0d0a3132372e302e302e3120646f }

condition:
	$a0
}

        