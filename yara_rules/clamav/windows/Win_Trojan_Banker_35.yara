rule Win_Trojan_Banker_35
{
strings:
	$a0 = { 557191aaab15f1b40ac693c00ff9b2e77ed36f2d749a94ff4d34ef68bb8bdac7836d122113e1a8d3a01f68d0bda214f4467d900c3ac34645030f0aabb8363b8c58e54457f048 }
	$a1 = { c5ccd1331cd0b98d7c3f84421d81fb4b50d0e391423c624030caca620a2a10a020423bd6958c6b2dd41fe56364b758ca3c26ec9d7290909a7ba8c3c86c90e6ddf986a0777d0c83621221fdd6d6 }

condition:
	$a0 and $a1
}

        