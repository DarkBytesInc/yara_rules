rule Win_Trojan_Agent_33814
{
strings:
	$a0 = { 78655f62616b00ffffffff0d000000633a5c686974706f702e747874000000cda8d0c5bce0bfd8a3bad6d5d6b9c1acbdd300004156502e547261666669634d6f6e436f6e6e }

condition:
	$a0
}

        