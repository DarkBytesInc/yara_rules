rule Win_Trojan_Bancos_1192
{
strings:
	$a0 = { 267253d1865632f6770ca3a862362db32739dde2df15ebc305910e2a137ffe6fb7abff7667a62edbb9a414fc8600940b28fa4b7baacebbf56da211d5e84a462ead2db37f811c0433fcd1c06bc7d591a3cd4bf4c4f3cb556dd02462ff9015afd34c713e0247f7227d0d }

condition:
	$a0
}

        
