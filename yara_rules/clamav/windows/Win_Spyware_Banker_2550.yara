rule Win_Spyware_Banker_2550
{
strings:
	$a0 = { 7ee6bf8fb50e6255d0e524dc246e9444c0f1932f1b2ab678f1f60e20a34ffd423ecfeee15666a05e508142b9aaa0293ff3c4ef026da4beee23eb6ecbde65ec2a642195e187f34d147d75e2b90823c1a135c26cd89eccc4fa7bfdcf61bb0a9e92bc225596370484b194923bb60bf7dbaa872ce8c29ade0f8e57031c663385b152aa680305df1b515fbe760d8bed35e7dc72876ce9 }

condition:
	$a0
}

        