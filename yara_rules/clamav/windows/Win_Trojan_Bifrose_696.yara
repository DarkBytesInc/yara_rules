rule Win_Trojan_Bifrose_696
{
strings:
	$a0 = { 5644110a87db902fd656044df0bb4429c09003dd2b9d71c11183bdd8309fad894c2f2e0e0f19853e05188dd9e0812750ff95ec310389ebdc031b8bf88d9ded3211532de81979b27928fa11570a227d768ba3495018566a3804683710a05646abf9c36a4c682615753a18452ac753e86374378bc8fabd8f0f0ab51b0ff3a415236576801a36e380578d0e8551772c7e0700c30a019c40 }

condition:
	$a0
}

        