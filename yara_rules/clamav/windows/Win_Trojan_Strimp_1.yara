rule Win_Trojan_Strimp_1
{
strings:
	$a0 = { 6f622b28b8f9c76788de4ba23924ba09234293eb540a49b17786f610f8e589db66764c68a25c3903112a2ecabb18dc4151c7042439c75a99102ac47428845ab6b4b42e882694424c86e8cc79013c01753e803de07e5e0b5a357304d3b88cb240f112457eb4615068a0ba6ba8a40545b08b4ee8f57ca542e06028d2589b4c9bce08a5ea423be51257908c202d7073e468037574646f77 }

condition:
	$a0
}

        