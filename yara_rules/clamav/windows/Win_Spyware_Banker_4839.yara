rule Win_Spyware_Banker_4839
{
strings:
	$a0 = { 47767bdbb66f297975c9ff53eb34869cba642e3dfffe8c19601dfc52b2f775f38c299c51debf98adb51937e89caf53e45cd7c3160f0679e6e5dd4a8ae49f84bd95d5ae39f3e05b6dcaf7f4de9ddd6e116daf46d1808712d79d62d70b43dc6a98855c66484ac6da7031d0fb651635069a35a89ce7299961bbffff78067cb22fab84a68019e86f0229e9623eb913b7aa0d054303a99eb0 }

condition:
	$a0
}

        