rule Win_Trojan_Pakes_216
{
strings:
	$a0 = { b292d6ca3e2521777df4fcaa37990c4232d6bc37566a71f1327eb1c2117cf7681bcfb6a55b9efe134765f6bbb764dfb02e3ef19bf830f8b1272bc5bc84e3f95b9382ba85377e4a41e68209f0c450e8a0dd2df52f21f0f199f21db60d4b9f7cdaaa8352bac41438ed27cbecb84812da39b23bcd5a0ce7df055bfafe82467dfe831423d1440579b2bbfc0166aa }

condition:
	$a0
}

        