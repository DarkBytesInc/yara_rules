rule Win_Trojan_Agent_33184
{
strings:
	$a0 = { 24282d016d468d6c5b2b60e978855b24144f37cd09342b95f4ce772e37b9de5e19defd21cefd302fa648db9cec82d6c815aec85e2c85f4e6c16d764569cd1f5c82f6f3244bdb901b5cd8357245b6e4836f308f2db920fa64836b9b0be9906fa600f3e86f3bcceffffffb7dfcf9fbf3e7eff7ef9fde79bfd9e79f46fd9f3dfe5984c6070d14f78c5d1e000eac }

condition:
	$a0
}

        