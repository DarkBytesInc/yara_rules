rule Win_Worm_Gaobot_189
{
strings:
	$a0 = { 48b48cd65f9c7d2baf1947e9d7b58b84cc32e467aab6717a717900000000f61e8d0235ceecf1a0995e5955490a5466688f045dc0765720332a66d60a1cd4000000000927edaf73083a895f18120430b13d57e7b194813786b659c6943d96d159faef0000dc53798b02d239cf90ff9861e7dad2797e2fb2000050ab4a5ff39f1a4c6c535892af }

condition:
	$a0
}

        