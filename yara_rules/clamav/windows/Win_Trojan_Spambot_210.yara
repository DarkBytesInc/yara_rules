rule Win_Trojan_Spambot_210
{
strings:
	$a0 = { 59e7deffffffff2f89f99f0f80a252446f14ab0af04af297c311fde9799f039d67d7c2c8ed7d9affffffff1390047bb9ef05ae858cad076ffa4dff68604cca9b3d580162c3f220e3cf22d2e8fffffffcc5833f6fc33c8b342cd8f9f5e26f1cec305a8f0d4e159a6da9a180ff7f48 }

condition:
	$a0
}

        
