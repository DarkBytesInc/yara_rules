rule Win_Trojan_SdBot_923
{
strings:
	$a0 = { 61451d612965868ddfb06e2a79f0762d6aada3870860261546059641cac426eb54a83e1fab5dee0dc914c87e4c95827fb0553f732be92c81b053e9ae19671c595252633d990d0e6fc310188cc333de2e615a7e2e892321dc593fad516ef3659926b0be3ac48ff2a0ac8d8ef640ed8be892c1c215c0dd906d79248610bafceca9bd265977b0436640934c2a051322a811e3ff62c7428d }

condition:
	$a0
}

        