rule Win_Trojan_Spambot_87
{
strings:
	$a0 = { 65ccc47335a58df69941882da2cb1a90ffffffffa57b4bae180438844bc97d0a57f156cfef3b34876c83bec579396182f4022dcdffffffffba91c9d4ff98ccaefd26e61abc13995246c364bd3b15dcd2873bca8dfc4171b48ffeffff3d1d48d0061cfab02c5590dd02422f544602 }

condition:
	$a0
}

        
