rule Win_Trojan_Spambot_164
{
strings:
	$a0 = { af31a74d04abeaff1fff8338be51e63cd95fe921d7cbb02286e08003b686b4ffffffff390275f532cd8b82fc3bc4a1f31554d3238472cf6768b08f9cb8a335a59b8c0fffffffa707dd36024ebd56794368420e487bc22fe95eeba7ec09729f3385ffe1ff72b871f6d72dfb640a27 }

condition:
	$a0
}

        
