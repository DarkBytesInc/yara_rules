rule Win_Trojan_DNSChanger_185
{
strings:
	$a0 = { 2473074a2c8bb7473836f7df2b97b3df4125c71f2c7721e82bf907dfff20edef4e61b76a2479b6f56c31f7dfb756e3ef6c211f1c4261b7362bf8b6154043f7df83208e372b37e7ef6c21f72f838bb8492c89c3f46c21b6552821cdef3c61b7dea11db7f53431f7df8b7f1212ecea7a35b70d3bcc4caefcd78254ad309460b7ee2c77 }

condition:
	$a0
}

        