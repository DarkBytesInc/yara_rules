rule Win_Trojan_Pakes_918
{
strings:
	$a0 = { f6e4144d6a5d52912f6d696d75f13ed4760829d2929ce22576902255cb9274a34123376001f37cf6659d776ef59a1c7b7a50628ea0497564455f066f24366ace49972b8075907bd582973a3ae4a6658b8f4076fa7b06627cb670371891f3ee32fe978352e44ab539453f595390640bdcf6af0ebddc1b1c00016f7f9562957f86d47702c7a791236eac14e662 }

condition:
	$a0
}

        