rule Win_Trojan_Mybot_5316
{
strings:
	$a0 = { 3d3902141e40315448bb60a5603677a1d8656767184768f802586c821b58e44a43f5b3cba46756425f15359247fd0d9787235c4244270bbf431828a5f7916df8f32cf4f75b26cbf9f12be37ddd0d497432073a8419648117e3b3a1d71d70efbf0363ba3a8ebe83fa19d212cf53272131531e2df4a6252dc50827457a55631f9653e6d24f969e81c29413c8f42b2b0bcb59702df05f }

condition:
	$a0
}

        