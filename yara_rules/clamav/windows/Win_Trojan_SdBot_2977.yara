rule Win_Trojan_SdBot_2977
{
strings:
	$a0 = { 837967e53420f806b2b67f06ea9290cba4972a2e039db3068f7bab6c48269876820d7ed3efc5d8996402f416f0294c462aefdc836dc7f628ad3e31f5fd9853e8135bcd8872ebb7d7a9b86adc731ced09c2ba4a015804657e91e9b5d0fdbdd11a5685166ec698287ba7b493583bfadd6cb58b9e6ce13d13f230c4f31295951ef8ed78c1a8fd1b8faea8e5b770fbd86b2861ae3ac18d6f }

condition:
	$a0
}

        