rule Win_Trojan_Bifrose_393
{
strings:
	$a0 = { 65f65f5b608a5ce46ec658d469f65d9e4764553baa8eab78586f1842cf979551939d215ad12ca280d6f6116a38d0db405c8c1b5affa9bd7c5e06a8575fa985c043a519e1c9ea8e5073529c557a0ae7741b7b729a07c0a9543bcd705be3178afc3fa1b7d4927ac72c708d9f1de62e6e4d1026494967aa5e6c6bcca54880a266507fc8c594a8c724fa91226799 }

condition:
	$a0
}

        