rule Win_Trojan_Vundo_477
{
strings:
	$a0 = { 5955569044a9015731a3ae220c1c44c1e47995ccd69400575033c3402bc0008d84d892ce301bc1f234f8c6035853524af7d2d9e2cbefab42f1d75a50a7250250d92e3876cfe3b83c0cca98e02c065e587d8b0f512bc981a069aa2e9d41c50e631d43d78bdd51c8c9870379cde65c032410565e81c3876c7a52316a7d87020f5adebcd41181c208783de25a9f }

condition:
	$a0
}

        