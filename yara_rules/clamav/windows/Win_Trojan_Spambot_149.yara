rule Win_Trojan_Spambot_149
{
strings:
	$a0 = { cc7dd37ff17f65e44c82277a230ce9dbb533475b7ee4b413e3fff8ffffc8c8c08cc1f3d2a9c6090735ae70ec553bf12b30e1214b8e64ff16f5ff97e1e63178bede92f7d45fc77328d56e92fffff8ff0b2742b2e6f0b52f83b075c94b15f2fdad1527cb899966e71c14faffffff50 }

condition:
	$a0
}

        
