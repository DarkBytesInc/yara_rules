rule Win_Trojan_Packed_127
{
strings:
	$a0 = { eb0483a4bcce60eb0480bc0411e800000000812c24cac24100eb04646b88185de800000000eb04646b8818812c2486000000eb04646b88188b859cc24100eb04646b8818290424eb04646b8818eb04646b88188b0424eb04646b881889859cc24100eb04646b881858689f6f56b650e85d000000ebff }

condition:
	$a0
}

        