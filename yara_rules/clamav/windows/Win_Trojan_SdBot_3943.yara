rule Win_Trojan_SdBot_3943
{
strings:
	$a0 = { 98b228f98a7908e1e4bf989345ae0b4a12c3a1232f619749b935701a9f0b81d4ba9e06cba6bbecc3279dd6bd7782e9ae30008d6d015356ab5d177e36d1256314587a2cc58af55021e77f1c9679ae4b12d2c0a1a72a5d9609e1f5741a }

condition:
	$a0
}

        