rule Win_Worm_Stration_600
{
strings:
	$a0 = { 5c2e65786506002b774dd37d1334033075280fb9b7a0efffcdffbcb7bee1e0fcb6bebed2193635293f123b343e363f5a2fdbffffff7c5e4f6b4954585e4848735e5a4b3b00c2efebfacbe6e6e5e98a1b7b9fff77ff5652437541565633 }

condition:
	$a0
}

        
