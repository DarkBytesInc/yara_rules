rule Win_Worm_Bagle_62
{
strings:
	$a0 = { 704720be6c623e1b4fbb4a102c87fd2f54bee591db19cd60c1c2369160b5610483c9ac1fc0fe249a115dc91559e528306d926717857e9f7e921d420a19907e91f3dc7d365a79ec29a569165dc1051ec059c7386ce24ab487c47790a4744b11c68c4d9c194f476c7966876f831c52f0814c0c6cec249e8024ce843cf36dba59173a2b7b5b5777d0b1f8081692574965052bf38d1ffc1a }

condition:
	$a0
}

        