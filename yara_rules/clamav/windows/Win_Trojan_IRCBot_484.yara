rule Win_Trojan_IRCBot_484
{
strings:
	$a0 = { e8febfdad6166a3333f1334ab6a97bec7b0c37d4917a70e1a8d8c3b2f8c8a01e4ed5366ee5f1ef1e287b5692fcf600810a58b6dcaa883b7968b50130a1c37852bbbb3e418d65d524ae2c4434e31edf7cae9f7337bb9e5d628beb7edfae21ad88ef0c1b4552b2a72825a1dee6aab2552ee9bb540b0fc2ac58522538271c5fda45d395171cb8ec9df29648d9e024f753ec2f8e5e6d0e2c }

condition:
	$a0
}

        