rule Win_Trojan_Skintrim_19
{
strings:
	$a0 = { 825013e334c7fcfd00993da2c4d5ff66f4ea66b00f0ba2fa90fbd09d22b33f06b48b2ee0513f640320b0383504841a886149265acdfdb5a4fb79ab5cc9ad2f35aa8a779ae3ec43f12148cba5522fc773c5f102446722c150820ef7af7898c135e957d9d527fcde6dc13686e23e4cec5db860e20683b747a5e706b1fe705ac0a6624eae7358ced00e2b8b2355 }

condition:
	$a0
}

        