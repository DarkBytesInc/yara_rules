rule Win_Trojan_Vundo_362
{
strings:
	$a0 = { 50eb1fe8775eff46e97fba0000ffd6c356456a11e9e3810000cce9995a0000c3904be8f4020000908bc758e823fdffff8bdb90eb0fcc54ffd1ffd4ffd2e8b65eff46904190eb0de92e530000e8544fff46486ad3803dd5530010016687c0e9a104000085 }

condition:
	$a0
}

        