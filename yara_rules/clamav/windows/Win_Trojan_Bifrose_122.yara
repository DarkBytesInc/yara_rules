rule Win_Trojan_Bifrose_122
{
strings:
	$a0 = { c898664a9dc488ef270028b31f6f3febbda2044ba1780494d8ff3f1e1fc3952ea47e7e1c9cf190cb33853f4f581fc0a5c83cef758620e36aa300c04057d7fca60fdb561a8e7aec9a508b883c5959b4d5432a16493c792218e200c0bf23198c81dc2e54c18d62df34a2c0b65e57d6e0f04556f6c1df75ef3875e8b185236f4565 }

condition:
	$a0
}

        