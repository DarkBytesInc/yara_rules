rule Win_Trojan_Agent_33745
{
strings:
	$a0 = { 2da6c1d8852fb813e68151326548c9cb8f0ee680a8ed282b1257e268faf5963aa7628d6e087fb4cdfb45fe1c0551317822a1939b86b6dfd8763efb41db5709b6f53c668fa4fe9ffdbc75e815432f749155f3b86b93262e8a0742c513b5e1e6abc3332aa18d8ec1aa8ebc9ff637b463c273f005204ab67e817e6a8492bd5dbe5b2064a9119f1d97d33de6d839 }

condition:
	$a0
}

        