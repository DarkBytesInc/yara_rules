rule Win_Trojan_Spambot_134
{
strings:
	$a0 = { 5a155a987ee7fffffff0f286a00825266ff0725765abb2c6e8e6f47defd05fda1e3316c9ffffffffe9a0ee22e3ee04bb9098f5d21b69e7b542bae4239c637d869afd44613363a634ffffdfef34a211cd356e306d3e8689967743775a25a02915c5fd104c003dc0ffffffa60ebe82 }

condition:
	$a0
}

        
