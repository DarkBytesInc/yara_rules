rule Win_Trojan_Bluntman_1
{
strings:
	$a0 = { 8b7d08893d748a40006a006a476858ab4000ff7508e8e0120000ff359c82400068ffac400068488e4000e8c716000083c40cff359c824000e80117000083c40489c76a005768488e4000ff7508e8a8120000 }

condition:
	$a0
}

        