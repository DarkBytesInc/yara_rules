rule Win_Trojan_Mybot_4706
{
strings:
	$a0 = { c7cdc1ef3ec2440c97ffeec87e1bc421394bd333e81dba0d23d12fee0c835e494fa6a2a9355562802e790d09eb1c1c445d3ece8a2297fdbf9b1b2770552b44922b68aa5161065b9d8021ce5d827c9c26d4cae25d4b40e95a8b1d8e616e38b3c0e3a9161ec25fc591db4f94cffcbe7416578cc63f7b12af2710961d90da70310fb740a6b453b7c9994c0cc2bcf9dba54827f794ce6ac0 }

condition:
	$a0
}

        