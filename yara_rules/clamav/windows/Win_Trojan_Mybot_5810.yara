rule Win_Trojan_Mybot_5810
{
strings:
	$a0 = { 9eb4fbdc874a9a150606a7ff5f62f0ea72d9f5571784bcc45791147a3b4ad48da5d4b01398e9f97f5e80f05126ca0d75a3de9186b6443870dc0a62d236a7a7d12443a7e0b25caa33c7121e75105393692610b33e4fcd52ac8d207ebc2201e15319fa946f4f203cb562965a193d34616e5836d32fca7ce8c81c85c81525feef6165e685abe5b6ca8b308d736983b5a79ba07711adcbbe }

condition:
	$a0
}

        