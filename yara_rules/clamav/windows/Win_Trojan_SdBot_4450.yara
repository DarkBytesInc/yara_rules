rule Win_Trojan_SdBot_4450
{
strings:
	$a0 = { c6246024b2851dc2fc708fae89e7fb0b1a2af423b06c58a84c5f8376c433b5ffc73f5963318e6f38fe71d05b33277b190598ffc9a3f26df10582d7ff62a37947f7cae6c4ea634b6537b7bfc6ff8b13d288ae9e9732ff8242cf1f5286bd15ff7027eab2aef544a6ffc7e8f382c7a5476fff49b5f37a06d42cafff38a6273d167c57a18bc9607f568937a56e96ffcb2bc2b5de24d1 }

condition:
	$a0
}

        