rule Win_Trojan_Mybot_5335
{
strings:
	$a0 = { c3f000cb4a48eadd2e3819635b7d42a36ca7b640e14204d35571b7f09d7ab9d48743fb6fbbc90c9be78eaf8498442b531da7c16800e4f6f151f94aaa5e7a454d1653c26f17d40f008cec59f343a859c639b734e5197403ede2a08f0e6411aeaed8e56fd2741131ed7b491669cb168147ef4c2d604e6a5f2584e3f9f0269f769fdedc12c6a45b10b84e98ed6083c18d9ca56594975eb9 }

condition:
	$a0
}

        