rule Win_Trojan_Small_3560
{
strings:
	$a0 = { c74043428646304593910f730dd7145457e7433433226fdb8a1fe70844634094d11e9590cf7d12612d9a6939db9825d61433d7042e5532277716e72eb85e1b0783ae2e878abfd34542a37fa84765 }

condition:
	$a0
}

        