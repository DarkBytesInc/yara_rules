rule Win_Trojan_IRCBot_403
{
strings:
	$a0 = { 1e56dc6f3debfc653cc165595a5af30bf7cd10d05d7eb9742f5f4d42ca28f05aacdf90c3453987434304a0da03017de988183c93dee7176f39536d6abf9b4b572ff5784715e4d4f7016fa1cf95dc9e1fb281bdb329c03eecaa7f9fdc242135ae288be27a7cb076e5876b2db420d0bb977abaaccb9d7ea9b9f3a5 }

condition:
	$a0
}

        
