rule Win_Trojan_Agent_35727
{
strings:
	$a0 = { 555e5d0f578d384781c7ec5f50f053680ae596a2c3b4880135dd60c1cb944be8eb00adbba04f1a798bdc1581c308b240ae3c0033e34c44bcc8427b3c018b845b5657538358e4c19c17489aeb529001ab80c1e93d33ce1d03ccb97c121373246863b68cc7b4be945e47a71f628ec05333dc03dd785be652ecd6795a0f5c241051cccb6e6f5159e3c3dc0e52e0 }

condition:
	$a0
}

        