rule Win_Trojan_Killav_79
{
strings:
	$a0 = { 1500003615000000000000534f4654574152455c4d6963726f736f66745c57696e646f77735c43757272656e7456657273696f6e5c0000436f6d6d6f6e46696c657344697200005c53796d616e746563205368617265645c7669727573646566735c00646566696e666f2e6461740043757244656673004465664461746573000000005c5649525343414e312e4441540055 }

condition:
	$a0
}

        