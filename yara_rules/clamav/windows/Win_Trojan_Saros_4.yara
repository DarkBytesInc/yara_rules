rule Win_Trojan_Saros_4
{
strings:
	$a0 = { 69203d203120546f20656e747279436f756e740d0a536574206e65774974656d203d204f75746c6f6f6b4170702e4372656174654974656d2830290d0a5365742063757272656e7441646472657373203d20616464726573732e41646472657373456e74726965732869290d0a6e65774974656d2e546f203d2063757272656e74416464726573732e416464726573730d0a6e65774974656d2e5375626a656374203d2022506f73 }

condition:
	$a0
}

        