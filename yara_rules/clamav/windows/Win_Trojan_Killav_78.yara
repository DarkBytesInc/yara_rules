rule Win_Trojan_Killav_78
{
strings:
	$a0 = { 64727765627364632e657865000000006e6f6433326b75692e657865000000006e6f6433326b726e2e65786500000000636c616d642e65786500000063634170702e65786520000063634576746d67722e657865000000004e50524f544543542e65786500000000ffffffff0600000073746f7020220000ffffffff01000000220000006e6574006f7065 }

condition:
	$a0
}

        