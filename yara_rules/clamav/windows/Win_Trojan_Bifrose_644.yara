rule Win_Trojan_Bifrose_644
{
strings:
	$a0 = { 303fb175510b698fe9db1b3f66dd644fa28968c18e28fc5c16c2162b03b7d7de3c7d98fec2891ddf8838b431975fd46b7b48f4e4b06fb7d432295a013d9c67c680969c7bee409a22cb534120816c435c0846645282fd36ab1dba3a99fe7af15ee7af127564662e925cc9952baa8f99b4d113a87e1dc2ed215626195951c7b24b0bcb74a6e231fdf593621e15108b85a611770ac46289 }

condition:
	$a0
}

        