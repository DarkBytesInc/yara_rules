rule Win_Trojan_Agent_707
{
strings:
	$a0 = { 0bbe03b7751e95e6f014d043e57ca12a5258e9dc731f4583868c37fa18b53cbda571ee492529ed736441c1f9bb74a1842dd87f3dc6c2150966dc82cb9206bc02a2f5c6ad0db580b9d3ad2e61414193307f79dd9b9a783a3efd99e8fb65210d46bfe2705f702b30dad7c0e48a99b2c6d11eb1b7d45334fa0cf3336248db2f5a6d956ffb8a6bdf1692b319147eb8feda17208544b4 }

condition:
	$a0
}

        