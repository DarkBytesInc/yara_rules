rule Win_Spyware_433_2
{
strings:
	$a0 = { 9471a59b31b94d21a83d7bf934299097079681593e6565697c674d959d740cde204a43dde73537aca3194732e381acdd325c766b88cecf56f0c9583aa7e448b46ee47c308e0df897475520ed3d5b8747f227bacf4755f676cb012d2c3c1738b9 }

condition:
	$a0
}

        