rule Win_Spyware_Delf_1771
{
strings:
	$a0 = { 308127100123723133286c42474f4846262601c00a031f5f797b657010476064758280115683200a03456d657172c4e0c3026930004e38f5f4bb9f848a89889eef300460ac67199c6921b8ce8a25bedf98a0821f0340a0c391aab6a7c1434652066838bbf1cbc7c3b05c586baf237861023138969dc9ed009e9085f278 }

condition:
	$a0
}

        