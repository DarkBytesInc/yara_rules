rule Win_Trojan_IRCBot_84
{
strings:
	$a0 = { 4adad60f533cbc81eca38fa14422348f0b27270edc802dc4575f031bba92d793612b8ae3e7414ae6cca86ce7a0a8cef79d42564c6e592b8116e1f77db87e4dbd386b17e4390f135cbae8f29816905d025d8bd54b14bab8c74f1b65851ffc646a05080307fceac6b493aeb80415c90fe4c6cfe762569f18c3273c717a063abc7bdb8d419f987a05d04610b722e4b7b4d3357daaa21f9a }

condition:
	$a0
}

        